from fastapi import APIRouter, UploadFile, File, Depends
from app.services.scanner import scan_file
from app.services.jwt_guard import get_current_user
from app.db.mongo import scan_collection

router = APIRouter()

@router.post("/")
async def scan_uploaded_file(
    file: UploadFile = File(...),
    user: str = Depends(get_current_user)
):
    return await scan_file(file, user)

@router.get("/history")
def get_scan_history(user_email: str = Depends(get_current_user)):
    scans = list(
        scan_collection.find(
            {"user_email": user_email},
            {"_id": 0}
        ).sort("scanned_at", -1)
    )
    return scans

@router.get("/stats")
def scan_stats(user_email: str = Depends(get_current_user)):
    total = scan_collection.count_documents({"user_email": user_email})
    malware = scan_collection.count_documents({
        "user_email": user_email,
        "malicious": True
    })
    safe = total - malware

    return {
        "total_scans": total,
        "malware_found": malware,
        "safe_files": safe
    }
