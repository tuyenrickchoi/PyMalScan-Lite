 PyMalScan-Lite
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
python gui/main_window.py

# Giao diện dòng lệnh (CLI)
python main.py
 Cơ chế đánh giá
Dự án sử dụng kỹ thuật Heuristic Analysis để dự đoán ý đồ của tệp dựa trên "bộ công cụ" (DLL/Functions) mà tệp đó yêu cầu từ Windows API, giúp phát hiện cả những mẫu mã độc mới chưa có trong cơ sở dữ liệu.
