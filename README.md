<img width="1206" height="841" alt="image" src="https://github.com/user-attachments/assets/8fb3efcc-0564-44e6-8cac-3d5addf95d3f" /> PyMalScan-Lite
PyMalScan-Lite là một công cụ phân tích tĩnh (Static Analysis) nhẹ dành cho các tệp thực thi Windows (PE files). Ứng dụng giúp nhận diện các bất thường về bảo mật và đánh giá mức độ rủi ro của tệp mà không cần thực thi mã code.

 Tính năng nổi bật
Phân tích PE Header chi tiết: Trích xuất thông tin Machine type, Compile time, và Subsystem.

Kiểm tra Entropy (Độ hỗn loạn): Tự động phát hiện các Section có entropy cao (>7.0) — dấu hiệu điển hình của việc tệp bị nén (packed) hoặc mã hóa để che giấu mã độc.

Đánh giá rủi ro Import (Heuristic Scoring):

Phát hiện các Hàm nguy hiểm (Dangerous Functions) như ShellExecuteA, InternetOpenA.

Nhận diện các DLL nhạy cảm có quyền can thiệp hệ thống/mạng (advapi32.dll, wininet.dll).

Tự động tính toán Import Risk Score để đưa ra kết luận về độ an toàn của tệp.

Kết hợp Đa phương thức: Tra cứu Database cục bộ (Signature Matching) kết hợp với VirusTotal API.

 Yêu cầu hệ thống
Python 3.8+

Thư viện: pefile, PyQt5, requests

Cây Thư mục
PyMalScan-Lite/
├── api/
│   └── virustotal_api.py      # Kết nối và truy vấn API VirusTotal
├── database/
│   ├── db_manager.py          # Quản lý cơ sở dữ liệu (SQLite)
│   └── signatures.db          # File database chứa mã nhận diện (signatures)
├── scanner/
│   ├── hash_scanner.py        # Quét mã độc dựa trên mã băm (MD5/SHA256)
│   └── pe_analyzer.py         # Phân tích cấu trúc file thực thi (PE file)
├── utils/
│   └── file_utils.py          # Các công cụ hỗ trợ xử lý file
├── gui_main.py                # Giao diện người dùng (PyQt/Tkinter)
├── main.py                    # Điểm chạy chương trình chính (CLI)
└── requirements.txt           # Danh sách thư viện cần thiết

 Cài đặt & Sử dụng
Tải mã nguồn:

Bash

git clone https://github.com/your-username/PyMalScan-Lite.git
cd PyMalScan-Lite
Cài đặt thư viện:

Bash

pip install -r requirements.txt
Chạy ứng dụng:

Bash

# Giao diện đồ họa (GUI)
<img width="1206" height="841" alt="image" src="https://github.com/user-attachments/assets/a683b947-5110-4dea-b2c0-ade34d1c8b04" />


# Giao diện dòng lệnh (CLI)
python main.py
 Cơ chế đánh giá
Dự án sử dụng kỹ thuật Heuristic Analysis để dự đoán ý đồ của tệp dựa trên "bộ công cụ" (DLL/Functions) mà tệp đó yêu cầu từ Windows API, giúp phát hiện cả những mẫu mã độc mới chưa có trong cơ sở dữ liệu.
