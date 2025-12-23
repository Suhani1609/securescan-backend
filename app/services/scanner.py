import hashlib
from fastapi import UploadFile
from datetime import datetime

from app.services.virustotal import check_hash_virustotal
from app.db.mongo import scan_collection


async def scan_file(file: UploadFile, user_email: str):
    # Read file bytes
    file_bytes = await file.read()

    # Generate SHA256 hash
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    # VirusTotal check
    vt_result = check_hash_virustotal(sha256_hash)

    malicious = False
    threat_level = "SAFE"
    detections = 0

    if vt_result["found"]:
        detections = vt_result["detections"]

        if detections >= 7:
            threat_level = "HIGH"
            malicious = True
        elif detections >= 3:
            threat_level = "MEDIUM"
            malicious = True
        elif detections > 0:
            threat_level = "LOW"
            malicious = True

    # Prepare scan document
    scan_data = {
        "user_email": user_email,   # 🔐 LINK TO USER
        "filename": file.filename,
        "filesize": len(file_bytes),
        "sha256": sha256_hash,
        "malicious": malicious,
        "threat_level": threat_level,
        "detections": detections,
        "scanned_at": datetime.utcnow()
    }

    # Save to MongoDB
    scan_collection.insert_one(scan_data)

    # Return API response
    return {
        "filename": file.filename,
        "filesize": len(file_bytes),
        "sha256": sha256_hash,
        "malicious": malicious,
        "threat_level": threat_level,
        "detections": detections,
        "message": "Scan completed & saved for user"
    }
