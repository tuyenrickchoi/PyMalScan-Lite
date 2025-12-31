import os
from scanner import hash_scanner, pe_analyzer
from api import virustotal_api
from database.db_manager import DatabaseManager

# --- KHỞI TẠO ĐỐI TƯỢNG DATABASE ---
db_handler = DatabaseManager()

def scan_file(filepath, scan_mode='quick'):
    
    report = {
        "filepath": filepath,
        "is_safe": True,
        "detections": {}
    }

    print(f"\n{'='*80}")
    print(f"BẮT ĐẦU QUÉT: {os.path.basename(filepath)}")
    print(f"Chế độ: {scan_mode.upper()} | Đường dẫn: {filepath}")
    print(f"{'='*80}\n")
    
    # 1. TÍNH TOÁN HASH (Luôn chạy)
    print("📌 [BƯỚC 1/4] TÍNH TOÁN HASH...")
    hashes = hash_scanner.get_file_hashes(filepath)
    if hashes['status'] != 'success':
        print(f"    ❌ Lỗi: {hashes['message']}")
        return report 
        
    report['detections']['hash'] = hashes
    print(f"    ✓ MD5:    {hashes['md5']}")
    print(f"    ✓ SHA256: {hashes['sha256']}\n")
    
    # 2. TRA CỨU DATABASE CỤC BỘ
    print("📌 [BƯỚC 2/4] TRA CỨU DATABASE CỤC BỘ...")
    local_detection = db_handler.search_signature(hashes['md5']) 
    
    if local_detection:
        report['is_safe'] = False
        report['detections']['local_db'] = {"detected": True, "malware_name": local_detection}
        print(f"    🚨 PHÁT HIỆN MÃ ĐỘC: {local_detection}")
    else:
        report['detections']['local_db'] = {"detected": False}
        print("    ✓ Không tìm thấy trong CSDL cục bộ.")
    print()

    # 3. TRA CỨU VIRUSTOTAL API
    print("📌 [BƯỚC 3/4] TRA CỨU VIRUSTOTAL...")
    vt_report = virustotal_api.get_vt_report(hashes['sha256'])
    report['detections']['virustotal'] = vt_report

    if vt_report['status'] == 'success':
        if vt_report['verdict'] == 'MALICIOUS':
            report['is_safe'] = False
            print(f"    🚨 PHÁT HIỆN: {vt_report['detected_by']}/{vt_report['total_scanners']} antivirus đánh dấu NGUY HIỂM")
        elif vt_report['verdict'] == 'NOT_FOUND':
            print("    ℹ️  Hash chưa có trong VirusTotal (file mới/ít phổ biến)")
        else:
            print(f"    ✓ Sạch: {vt_report['detected_by']}/{vt_report['total_scanners']} phát hiện")
    else:
        print(f"    ⚠️  Lỗi API: {vt_report['message']}")
    print()

    # 4. PHÂN TÍCH PE HEADER CHI TIẾT (Chỉ Deep Scan)
    if scan_mode == 'deep':
        print("📌 [BƯỚC 4/4] PHÂN TÍCH CHUYÊN SÂU PE HEADER...")
        pe_info = pe_analyzer.analyze_pe_header(filepath)
        report['detections']['pe_analysis'] = pe_info
        
        if pe_info.get('status') == 'success' and pe_info.get('is_pe'):
            _print_detailed_pe_analysis(pe_info)
        elif pe_info.get('status') == 'Not a PE file':
            print("    ℹ️  Không phải file Windows thực thi (PE), bỏ qua phân tích.")
        else:
            print(f"    ❌ Lỗi: {pe_info.get('message')}")
        print()
            
    # 5. KẾT LUẬN CUỐI CÙNG
    print(f"\n{'='*80}")
    print("KẾT LUẬN CUỐI CÙNG:")
    print(f"{'='*80}")
    if report['is_safe']:
        print("✅ TỆP ĐƯỢC ĐÁNH GIÁ: AN TOÀN (CLEAN)")
    else:
        print("🚨 TỆP ĐƯỢC ĐÁNH GIÁ: NGUY HIỂM (MALWARE DETECTED)")
    print(f"{'='*80}\n")
    
    return report


def _print_detailed_pe_analysis(pe_info):
    """In chi tiết phân tích PE giống VirusTotal"""
    
    # --- BASIC PROPERTIES ---
    print("\n    ┌─ BASIC PROPERTIES")
    bp = pe_info.get('basic_properties', {})
    print(f"    │  File Type:     {bp.get('file_type', 'N/A')}")
    print(f"    │  Magic:         {bp.get('magic', 'N/A')}")
    print(f"    │  Packed:        {bp.get('packed', 'Unknown')}")
    
    # --- HISTORY ---
    print("\n    ┌─ HISTORY")
    hist = pe_info.get('history', {})
    print(f"    │  Creation Time: {hist.get('creation_time', 'N/A')}")
    
    # --- FILE HEADER ---
    print("\n    ┌─ FILE HEADER")
    fh = pe_info.get('file_header', {})
    print(f"    │  Machine:                {fh.get('machine', 'N/A')}")
    print(f"    │  Compilation Timestamp:  {fh.get('compilation_timestamp', 'N/A')}")
    print(f"    │  Number of Sections:     {fh.get('number_of_sections', 'N/A')}")
    print(f"    │  Characteristics:        {', '.join(fh.get('characteristics', []))}")
    
    # --- OPTIONAL HEADER ---
    print("\n    ┌─ OPTIONAL HEADER")
    oh = pe_info.get('optional_header', {})
    print(f"    │  Magic:                  {oh.get('magic', 'N/A')}")
    print(f"    │  Linker Version:         {oh.get('linker_version', 'N/A')}")
    print(f"    │  Entry Point:            {oh.get('address_of_entry_point', 'N/A')}")
    print(f"    │  Image Base:             {oh.get('image_base', 'N/A')}")
    print(f"    │  Size of Image:          {oh.get('size_of_image', 0):,} bytes")
    print(f"    │  Subsystem:              {oh.get('subsystem', 'N/A')}")
    print(f"    │  DLL Characteristics:    {', '.join(oh.get('dll_characteristics', []))}")
    
    # --- SECTIONS ---
    print("\n    ┌─ SECTIONS")
    sections = pe_info.get('sections', [])
    if sections:
        print(f"    │  {'Name':<10} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12} {'Entropy':<8}")
        print(f"    │  {'-'*10} {'-'*12} {'-'*12} {'-'*12} {'-'*8}")
        for sec in sections:
            name = sec['name'][:10]
            vaddr = sec['virtual_address']
            vsize = f"{sec['virtual_size']:,}"
            rsize = f"{sec['raw_size']:,}"
            entropy = f"{sec['entropy']:.2f}"
            print(f"    │  {name:<10} {vaddr:<12} {vsize:<12} {rsize:<12} {entropy:<8}")
            
            # Cảnh báo nếu entropy cao (có thể bị pack/encrypt)
            if sec['entropy'] > 7.0:
                print(f"    │      ⚠️  High entropy detected (>7.0) - Possibly packed/encrypted")
    else:
        print("    │  No sections found.")
    
    # --- IMPORTS ---
    print("\n    ┌─ IMPORTS (Top 5 DLLs)")
    imports = pe_info.get('imports', [])
    if imports:
        for i, imp in enumerate(imports[:5], 1):
            dll = imp['dll']
            total = imp['total_functions']
            funcs = imp['functions'][:5]  # 5 functions đầu
            print(f"    │  [{i}] {dll} ({total} functions)")
            for func in funcs:
                print(f"    │      - {func}")
    else:
        print("    │  No imports found.")
    
    # --- EXPORTS ---
    print("\n    ┌─ EXPORTS")
    exports = pe_info.get('exports', [])
    if exports:
        print(f"    │  Total: {len(exports)} exported functions")
        for i, exp in enumerate(exports[:10], 1):  # 10 exports đầu
            print(f"    │  [{i}] {exp['name']} (Ordinal: {exp['ordinal']}, Address: {exp['address']})")
    else:
        print("    │  No exports found.")
    
    # --- RESOURCES ---
    print("\n    ┌─ RESOURCES")
    resources = pe_info.get('resources', [])
    if resources:
        print(f"    │  Total: {len(resources)} resources")
        for i, res in enumerate(resources[:5], 1):
            print(f"    │  [{i}] Type: {res['type']}, Size: {res['size']:,} bytes")
    else:
        print("    │  No resources found.")
    
    # Cảnh báo bảo mật
    _print_security_warnings(pe_info)


def _print_security_warnings(pe_info):
    """In các cảnh báo bảo mật dựa trên phân tích"""
    print("\n    ┌─ SECURITY WARNINGS")
    
    warnings = []
    
    # 1. Kiểm tra ASLR/DEP
    dll_chars = pe_info.get('optional_header', {}).get('dll_characteristics', [])
    if 'DYNAMIC_BASE (ASLR)' not in dll_chars:
        warnings.append("⚠️  ASLR not enabled - vulnerable to memory attacks")
    if 'NX_COMPAT (DEP)' not in dll_chars:
        warnings.append("⚠️  DEP/NX not enabled - vulnerable to code execution")
    
    # 2. Kiểm tra các DLL nguy hiểm
    dangerous_dlls = ['ws2_32.dll', 'wininet.dll', 'urlmon.dll']
    imports = pe_info.get('imports', [])
    for imp in imports:
        if imp['dll'].lower() in dangerous_dlls:
            warnings.append(f"⚠️  Imports suspicious DLL: {imp['dll']} (Network capability)")
    
    # 3. Kiểm tra số lượng imports bất thường
    if len(imports) > 50:
        warnings.append(f"⚠️  Unusual number of imported DLLs: {len(imports)} (>50)")
    
    # 4. Kiểm tra sections với entropy cao
    sections = pe_info.get('sections', [])
    high_entropy_sections = [s for s in sections if s['entropy'] > 7.5]
    if len(high_entropy_sections) >= 2:
        warnings.append(f"⚠️  Multiple high-entropy sections detected (possible packer/crypter)")
    
    if warnings:
        for w in warnings:
            print(f"    │  {w}")
    else:
        print("    │  ✓ No obvious security warnings detected.")


# --- Phần chạy thử ---
if __name__ == "__main__":
    
    if virustotal_api.VT_API_KEY == "API_KEY_CUA_BAN_O_DAY":
        print("!!! CẦN THIẾT LẬP API KEY !!!")
        print("Vui lòng chỉnh sửa file 'api/virustotal_api.py' với API Key của bạn.")
        print()
        
    path = input("Nhập đường dẫn file cần quét: ").strip().replace('"', '')
    
    if os.path.exists(path):
        mode = input("Chọn chế độ (quick/deep): ").strip().lower()
        if mode not in ['quick', 'deep']:
            print("Chế độ không hợp lệ. Sử dụng 'quick' mặc định.")
            mode = 'quick'
        scan_file(path, mode)
    else:
        print("❌ Lỗi: File không tồn tại!")