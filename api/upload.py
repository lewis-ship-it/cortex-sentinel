# api/upload.py

import os
import uuid
import shutil
import logging
from fastapi import APIRouter, UploadFile, HTTPException

from scanner.sast_engine import SASTScanner
from task_queue.redis_client import push
from task_queue.queues import MOBILE_QUEUE
from core.job_tracker import create_job

router = APIRouter()

UPLOAD_DIR    = "uploads"
MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MB
ALLOWED_EXTENSIONS = {".zip", ".apk"}


@router.post("/upload")
async def upload_file(file: UploadFile):
    """
    Accepts:
      - .zip  → immediate SAST scan, findings returned directly
      - .apk  → enqueued to MOBILE_QUEUE for full mobile analysis
    """
    filename = file.filename or ""
    ext      = os.path.splitext(filename)[1].lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            400,
            f"Unsupported file type '{ext}'. Accepted: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    unique_name = f"{uuid.uuid4().hex}_{filename}"
    save_path   = os.path.join(UPLOAD_DIR, unique_name)

    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "File too large. Maximum size is 100 MB.")

    with open(save_path, "wb") as f:
        f.write(content)

    logging.info(f"[UPLOAD] Saved {ext} to {save_path}")

    if ext == ".apk":
        return await _handle_apk(save_path, filename)
    if ext == ".zip":
        return await _handle_zip(save_path)


async def _handle_apk(apk_path, original_filename):
    job_id = str(uuid.uuid4())
    create_job(job_id, original_filename)
    push(MOBILE_QUEUE, {"job_id": job_id, "apk_path": apk_path})
    logging.info(f"[UPLOAD] APK enqueued. job_id={job_id}")
    return {
        "job_id":  job_id,
        "type":    "mobile_scan",
        "message": "APK queued for analysis. Poll /job/{job_id} for status.",
    }


async def _handle_zip(zip_path):
    # FIX: removed redundant zipfile.extractall() — SASTScanner.scan_zip() handles
    # its own extraction internally, so double-extraction was wasteful and left
    # orphaned temp directories.
    scanner  = SASTScanner()
    findings = scanner.scan_zip(zip_path)
    logging.info(f"[UPLOAD] ZIP SAST complete. {len(findings)} findings.")
    return {
        "type":     "sast_scan",
        "findings": findings,
    }



