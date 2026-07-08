# BTL Đề tài 2: Zero-Knowledge Relay Server – Gửi báo cáo công ty qua server trung gian
Hệ thống bảo mật gửi báo cáo nội bộ doanh nghiệp áp dụng mô hình **Zero-Knowledge (Không tri thức)** và **End-to-End Encryption (Mã hóa đầu cuối - E2EE)** sử dụng thuật toán **AES-256-GCM**. Server trung gian chỉ điều phối và ghi log, hoàn toàn không thể đọc được nội dung bản rõ của báo cáo.

## 🛠 1. Cấu trúc thư mục dự án
```text
CODE BTL
│
├── server_relay.py       # Server trung gian (nhận, kiểm tra replay, ghi log, chuyển tiếp)
├── app_clients.py        # Web App giao diện cho cả Người gửi & Người nhận (chạy cổng 8001)
├── server.log            # File lưu trữ audit log hệ thống
└── README.md             # Hướng dẫn chạy và kịch bản demo

### 🛠 2. Cài đặt hệ thống
2.1. Cài đặt thư viện
pip install fastapi uvicorn là của file server relay ||
pip install pycryptodome của file clients
2.2. Yêu cầu hệ thống
Python 3.x trở lên.
Thư viện mã hóa mật mã học pycryptodome.
2.3. ác bước khởi chạy:
Bước 1: Bật Server trung gian, mở Terminal mới và gõ
python server_relay.py
Bước 2: Chạy Client Sender để gửi báo cáo
python client_sender.py
Bước 3: Mở 1 tab mới và cập nhật vào địa chỉ
http://127.0.0.1:8001/docs