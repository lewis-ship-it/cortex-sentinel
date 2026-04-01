# api/upload.py

from fastapi import APIRouter, UploadFile, HTTPException
import zipfile
import os
import uuid
import shutil

from scanner.code_analyzer import CodeAnalyzer

router = APIRouter()

UPLOAD_DIR = "uploads"


@router.post("/upload")
async def upload_zip(file: UploadFile):

    # Ensure upload directory exists
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Basic validation
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip files allowed")

    # Generate safe unique filename
    safe_name = f"{uuid.uuid4()}.zip"
    path = os.path.join(UPLOAD_DIR, safe_name)

    try:
        # Save file
        with open(path, "wb") as f:
            f.write(await file.read())

        # Extract safely
        extract_path = path.replace(".zip", "")
        os.makedirs(extract_path, exist_ok=True)

        with zipfile.ZipFile(path, 'r') as zip_ref:
            zip_ref.extractall(extract_path)

        # Analyze code
        analyzer = CodeAnalyzer()
        findings = analyzer.scan_directory(extract_path)

        return {
            "status": "success",
            "files_scanned": extract_path,
            "findings": findings
        }

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid ZIP file")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))