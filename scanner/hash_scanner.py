import hashlib

def get_file_hashes(filepath):
    """
    Tính toán cả MD5 và SHA256 của file.
    Trả về: Dictionary chứa md5 và sha256.
    """
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        
        with open(filepath, "rb") as f:
            # Đọc file theo từng miếng nhỏ (4KB) để không bị đơ máy nếu file nặng
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
                
        return {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest(),
            "status": "success"
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}