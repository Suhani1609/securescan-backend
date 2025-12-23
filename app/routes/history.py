from fastapi import APIRouter, Depends
from app.db.mongo import scan_collection
from app.services.jwt_guard import get_current_user

router = APIRouter()

@router.get("/")
def get_scan_history(user_email: str = Depends(get_current_user)):
    scans = scan_collection.find(
        {"user_email": user_email},
        {"_id": 0}
    ).sort("scanned_at", -1)

    return list(scans)
