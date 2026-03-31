from fastapi import APIRouter, UploadFile
import zipfile
import os

from scanner.code_analyzer import CodeAnalyzer

router = APIRouter()

UPLOAD_DIR = "uploads"

@router.post("/upload")
async def upload_zip(file: UploadFile):

    path = f"{UPLOAD_DIR}/{file.filename}"

    with open(path, "wb") as f:
        f.write(await file.read())

    extract_path = path.replace(".zip", "")
    
    with zipfile.ZipFile(path, 'r') as zip_ref:
        zip_ref.extractall(extract_path)

    analyzer = CodeAnalyzer()
    findings = analyzer.scan_directory(extract_path)

    return {"findings": findings}