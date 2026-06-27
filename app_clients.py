from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import requests
import secrets
import time
from Crypto.Cipher import AES

app = FastAPI(title="Company Encrypted Communication Client")

SHARED_KEY_HEX = "6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435"
shared_key = bytes.fromhex(SHARED_KEY_HEX)

# Giao diện HTML tích hợp CSS
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Hệ thống Gửi Báo Cáo E2EE</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; }}
        .container {{ display: flex; gap: 20px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); flex: 1; }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        textarea, input[type="text"] {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
        button {{ background-color: #3498db; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }}
        button:hover {{ background-color: #2980b9; }}
        .alert {{ padding: 10px; margin-top: 10px; border-radius: 4px; font-weight: bold; }}
        .success {{ background-color: #d4edda; color: #155724; }}
        .danger {{ background-color: #f8d7da; color: #721c24; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
    </style>
</head>
<body>
    <h1>🔒 Hệ Thống Gửi Báo Cáo Bảo Mật (Zero-Knowledge Relay)</h1>
    <hr>
    <div class="container">
        <div class="card">
            <h2>1. Client A (Người Gửi)</h2>
            <form action="/send" method="post">
                <label>Nội dung báo cáo rõ (Plaintext):</label>
                <textarea name="content" rows="4" required>BÁO CÁO TÀI CHÍNH QUÝ 2: Lợi nhuận đạt 5 tỷ VNĐ.</textarea>
                <button type="submit">Mã hóa & Gửi lên Server</button>
            </form>
            {send_result}
        </div>

        <div class="card">
            <h2>2. Client B (Người Nhận)</h2>
            <form action="/receive" method="post">
                <label>Nhập Mã Giao Dịch (Transaction ID):</label>
                <input type="text" name="tx_id" placeholder="Ví dụ: TX-A1B2" required>
                <input type="checkbox" name="tamper" value="true"> <i>Giả lập hack/sửa đổi gói tin tại Server</i><br><br>
                <button type="submit" style="background-color: #2ecc71;">Tải về & Giải mã</button>
            </form>
            {receive_result}
        </div>
    </div>
    
    <div class="card" style="margin-top:20px;">
        <h2>📋 Nhật ký hệ thống theo thời gian thực (Audit Log từ Server)</h2>
        <button onclick="location.reload()">Cập nhật Log</button>
        <pre>{log_content}</pre>
    </div>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def index(send_result: str = "", receive_result: str = ""):
    # Lấy log từ Server trung gian để hiển thị lên Web luôn
    try:
        log_res = requests.get("http://127.0.0.1:8000/logs").json()
        log_content = "".join(log_res.get("logs", []))
    except:
        log_content = "Không thể kết nối đến Relay Server..."
        
    return HTML_TEMPLATE.format(send_result=send_result, receive_result=receive_result, log_content=log_content)

@app.post("/send", response_class=HTMLResponse)
async def send_report(content: str = Form(...)):
    # Tiến hành mã hóa AES-GCM
    cipher = AES.new(shared_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(content.encode('utf-8'))
    
    tx_id = f"TX-{secrets.token_hex(3).upper()}"
    packet = {
        "transaction_id": tx_id,
        "session_id": "SS-WEB-101",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(5),
        "sender_id": "Client_A",
        "receiver_id": "Client_B",
        "encrypted_data": {
            "ciphertext": ciphertext.hex(),
            "iv": cipher.nonce.hex(),
            "tag": tag.hex()
        }
    }
    
    # Gửi qua API Server trung gian
    try:
        res = requests.post("http://127.0.0.1:8000/relay", json=packet)
        if res.status_code == 200:
            result_html = f"""<div class='alert success'>
                ✅ Gửi thành công!<br>
                <b>Mã giao dịch (TX ID):</b> <span style='color:blue; font-size:18px;'>{tx_id}</span><br>
                <small>Bản mã gửi đi: {ciphertext.hex()[:30]}...</small>
            </div>"""
        else:
            result_html = f"<div class='alert danger'>❌ Server từ chối: {res.text}</div>"
    except Exception as e:
        result_html = f"<div class='alert danger'>❌ Lỗi kết nối Server: {e}</div>"
        
    return await index(send_result=result_html)

@app.post("/receive", response_class=HTMLResponse)
async def receive_report(tx_id: str = Form(...), tamper: str = Form(None)):
    try:
        res = requests.get(f"http://127.0.0.1:8000/get_report/{tx_id}")
        if res.status_code != 200:
            return await index(receive_result=f"<div class='alert danger'>❌ Không tìm thấy TX ID này trên Server!</div>")
            
        packet = res.json()
        enc_data = packet["encrypted_data"]
        
        ciphertext_bytes = bytes.fromhex(enc_data["ciphertext"])
        iv_bytes = bytes.fromhex(enc_data["iv"])
        tag_bytes = bytes.fromhex(enc_data["tag"])
        
        # KỊCH BẢN KIỂM THỬ 3: GIẢ LẬP SỬA ĐỔI GÓI TIN (TAMPER)
        if tamper == "true":
            # Đổi bit cuối cùng của bản mã để giả lập hacker phá hoại dữ liệu
            ciphertext_bytes = ciphertext_bytes[:-1] + b'\x00'
            
        # Giải mã và kiểm tra toàn vẹn
        cipher = AES.new(shared_key, AES.MODE_GCM, nonce=iv_bytes)
        plaintext = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes).decode('utf-8')
        
        result_html = f"""<div class='alert success'>
            🔒 Xác thực E2EE thành công!<br>
            <b>Nội dung giải mã:</b> <span style='color:green;'>{plaintext}</span>
        </div>"""
    except ValueError:
        result_html = """<div class='alert danger'>
            🚨 DỮ LIỆU BỊ TAMPER/SỬA ĐỔI!<br>
            Hệ thống phát hiện lỗi sai lệch mã băm kiểm tra toàn vẹn (AES-GCM Auth Tag thất bại). Từ chối giải mã!
        </div>"""
    except Exception as e:
        result_html = f"<div class='alert danger'>❌ Lỗi: {e}</div>"
        
    return await index(receive_result=result_html)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8001)
    