import requests
import os

VT_API_KEY = os.getenv("VT_API_KEY")
VT_HASH_URL = "https://www.virustotal.com/api/v3/files/{}"

def check_hash_virustotal(file_hash: str):
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(VT_HASH_URL.format(file_hash), headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]
        suspicious = stats["suspicious"]

        detections = malicious + suspicious

        return {
            "found": True,
            "detections": detections,
            "stats": stats
        }

    return {
        "found": False,
        "detections": 0,
        "stats": {}
    }
