import requests
import time


VT_API_KEY = "5887fdb8f3cd0ab87c1bf6498c4371c4b8aa88cb4c454a39e96f7e9bf8104d29"
VT_API_URL = "https://www.virustotal.com/api/v3/files/"

def get_vt_report(sha256_hash):
    """
    Tra cứu báo cáo của Hash SHA256 trên VirusTotal.
    """
   

    # API Key được truyền qua Header
    headers = {
        "x-apikey": VT_API_KEY
    }
    
    # VirusTotal sử dụng hash SHA256 làm định danh file
    url = VT_API_URL + sha256_hash
    
    try:
        print("    -> Đang gửi truy vấn lên VirusTotal...")
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            
            # Lấy kết quả quét từ 70+ Antivirus
            stats = data['data']['attributes']['last_analysis_stats']
            
            # Tính tỷ lệ phát hiện
            detected = stats.get('malicious', 0) + stats.get('suspicious', 0)
            total = stats.get('harmless', 0) + detected + stats.get('timeout', 0) + stats.get('undetected', 0)
            
            return {
                "status": "success",
                "detected_by": detected,
                "total_scanners": total,
                "verdict": "MALICIOUS" if detected > 0 else "CLEAN"
            }
            
        elif response.status_code == 404:
            return {"status": "success", "detected_by": 0, "total_scanners": 0, "verdict": "NOT_FOUND"}
            
        elif response.status_code == 429:
            return {"status": "error", "message": "Vượt quá giới hạn Rate Limit của API (429 Too Many Requests)."}
            
        else:
            return {"status": "error", "message": f"Lỗi API: {response.status_code} - {response.text}"}
            
    except requests.exceptions.RequestException as e:
        return {"status": "error", "message": f"Lỗi kết nối mạng: {e}"}