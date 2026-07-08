from fastapi import FastAPI, Form, File, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel
from typing import Optional
import secrets
import time
import json
from Crypto.Cipher import AES

app = FastAPI(title="E2EE Integrated System (Client + Server)")

# ===================== PHẦN MÁY CHỦ (RELAY SERVER) =====================
USED_NONCES = set()
LOG_FILE = "server.log"
DB_REPORTS = {}

class EncryptedData(BaseModel):
    ciphertext: str
    iv: str
    tag: str

class ReportPacket(BaseModel):
    transaction_id: str
    session_id: str
    timestamp: int
    nonce: str
    sender_id: str
    receiver_id: str
    encrypted_data: EncryptedData
    data_type: str = "text"
    file_name: Optional[str] = None

def write_audit_log(level, tx_id, session_id, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] [TX: {tx_id}] [Session: {session_id}] {message}\n"
    try:
        print(log_entry.strip())
    except UnicodeEncodeError:
        print(log_entry.strip().encode("ascii", "replace").decode("ascii"))
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

@app.post("/relay")
async def relay_report(packet: ReportPacket):
    current_time = int(time.time())
    
    if abs(current_time - packet.timestamp) > 300:
        write_audit_log("WARN", packet.transaction_id, packet.session_id, "Từ chối: Timestamp quá hạn.")
        raise HTTPException(status_code=400, detail="Timestamp expired")
        
    if packet.nonce in USED_NONCES:
        write_audit_log("CRITICAL", packet.transaction_id, packet.session_id, f"Phát hiện REPLAY ATTACK! Nonce '{packet.nonce}' đã dùng.")
        raise HTTPException(status_code=400, detail="Replay Attack Detected")
        
    USED_NONCES.add(packet.nonce)
    DB_REPORTS[packet.transaction_id] = packet.model_dump() if hasattr(packet, "model_dump") else packet.dict()
    
    write_audit_log("INFO", packet.transaction_id, packet.session_id, f"Nhận & Chuyển tiếp thành công. Bản mã: {packet.encrypted_data.ciphertext[:20]}...")
    return {"status": "SUCCESS", "message": "Gói tin đã được xử lý và chuyển tiếp."}

@app.get("/get_report/{tx_id}")
async def get_report(tx_id: str):
    if tx_id not in DB_REPORTS:
        raise HTTPException(status_code=404, detail="Không tìm thấy giao dịch")
    return DB_REPORTS[tx_id]

@app.get("/logs")
async def get_logs():
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            return {"logs": f.readlines()}
    except FileNotFoundError:
        return {"logs": ["Chưa có log được ghi nhận."]}

# ===================== PHẦN MÁY KHÁCH (CLIENTS) =====================
SHARED_KEY_HEX = "6162636465666768696a6b6c6d6e6f707172737475767778797a303132333435"
shared_key = bytes.fromhex(SHARED_KEY_HEX)

HTML_HOME = """
<!DOCTYPE html>
<html>
<head>
    <title>Hệ thống Gửi Báo Cáo E2EE</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; text-align: center; }}
        h1 {{ color: #2c3e50; }}
        .container {{ display: flex; gap: 30px; justify-content: center; margin-top: 40px; }}
        .card {{ background: white; padding: 40px 30px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); width: 320px; transition: transform 0.2s, box-shadow 0.2s; }}
        .card:hover {{ transform: translateY(-5px); box-shadow: 0 8px 24px rgba(0,0,0,0.2); }}
        .card h2 {{ color: #2c3e50; margin-top: 10px; }}
        .card p {{ color: #7f8c8d; line-height: 1.6; }}
        .btn {{ display: inline-block; padding: 12px 30px; border-radius: 6px; text-decoration: none; color: white; font-weight: bold; font-size: 16px; margin-top: 15px; transition: background-color 0.2s; }}
        .btn-send {{ background-color: #3498db; }}
        .btn-send:hover {{ background-color: #2980b9; }}
        .btn-receive {{ background-color: #2ecc71; }}
        .btn-receive:hover {{ background-color: #27ae60; }}
        .icon {{ font-size: 60px; }}
    </style>
</head>
<body>
    <h1>🔒 Hệ Thống Gửi Báo Cáo Bảo Mật (Zero-Knowledge Relay)</h1>
    <p style="color: #7f8c8d; font-size: 16px;">Mã hóa đầu cuối AES-256-GCM | Server không đọc được nội dung</p>
    <hr>
    <p style="font-size: 18px; color: #2c3e50;">Chọn vai trò của bạn để bắt đầu:</p>
    <div class="container">
        <div class="card">
            <div class="icon">📤</div>
            <h2>Client A</h2>
            <p><b>Người Gửi</b> báo cáo</p>
            <p style="font-size: 13px;">Nhập nội dung văn bản hoặc tải file Word/PDF lên,<br>mã hóa E2EE rồi gửi qua Server trung gian.</p>
            <a href="/sender" class="btn btn-send">Vào trang Gửi →</a>
        </div>
        <div class="card">
            <div class="icon">📥</div>
            <h2>Client B</h2>
            <p><b>Người Nhận</b> báo cáo</p>
            <p style="font-size: 13px;">Nhập mã giao dịch TX ID để tải gói tin về,<br>giải mã và xem nội dung gốc hoặc tải file.</p>
            <a href="/receiver" class="btn btn-receive">Vào trang Nhận →</a>
        </div>
    </div>
</body>
</html>
"""

HTML_SENDER = """
<!DOCTYPE html>
<html>
<head>
    <title>Client A - Người Gửi | E2EE</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 750px; margin: 0 auto 20px auto; }}
        h1 {{ color: #2c3e50; text-align: center; }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
        textarea, input[type="text"] {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
        button {{ background-color: #3498db; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }}
        button:hover {{ background-color: #2980b9; }}
        .alert {{ padding: 15px; margin-top: 15px; border-radius: 4px; font-weight: bold; }}
        .success {{ background-color: #d4edda; color: #155724; }}
        .danger {{ background-color: #f8d7da; color: #721c24; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
        .nav {{ text-align: center; margin-bottom: 20px; }}
        .nav a {{ color: #3498db; text-decoration: none; font-weight: bold; margin: 0 10px; }}
        .nav a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">🏠 Trang chủ</a> | <a href="/receiver">📥 Sang trang Nhận (Client B) →</a>
    </div>
    <h1>📤 Client A - Người Gửi Báo Cáo</h1>
    
    <div class="card">
        <h2>✏️ Gửi Văn Bản</h2>
        <form action="/send" method="post">
            <label>Nội dung báo cáo rõ (Plaintext):</label>
            <textarea name="content" rows="4" required placeholder="Nhập nội dung cần mã hóa của bạn vào đây..."></textarea>
            <button type="submit">🔐 Mã hóa & Gửi lên Server</button>
        </form>
    </div>
    
    <div class="card">
        <h2>📎 Gửi File (Word / PDF)</h2>
        <form action="/send_file" method="post" enctype="multipart/form-data">
            <label>Tải lên File để mã hóa:</label>
            <input type="file" name="file" accept=".doc,.docx,.pdf" required style="margin: 10px 0; display: block;">
            <button type="submit" style="background-color: #e67e22;">📎 Mã hóa File & Gửi lên Server</button>
        </form>
    </div>
    
    {send_result}
    
    <div class="card">
        <h2>📋 Nhật ký hệ thống (Audit Log từ Server)</h2>
        <button onclick="location.reload()">🔄 Cập nhật Log</button>
        <pre>{log_content}</pre>
    </div>
</body>
</html>
"""

HTML_RECEIVER = """
<!DOCTYPE html>
<html>
<head>
    <title>Client B - Người Nhận | E2EE</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f6f9; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); max-width: 750px; margin: 0 auto 20px auto; }}
        h1 {{ color: #2c3e50; text-align: center; }}
        h2 {{ color: #2c3e50; border-bottom: 2px solid #2ecc71; padding-bottom: 10px; }}
        textarea, input[type="text"] {{ width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
        button {{ background-color: #2ecc71; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }}
        button:hover {{ background-color: #27ae60; }}
        .alert {{ padding: 15px; margin-top: 15px; border-radius: 4px; font-weight: bold; }}
        .success {{ background-color: #d4edda; color: #155724; }}
        .danger {{ background-color: #f8d7da; color: #721c24; }}
        pre {{ background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; }}
        .nav {{ text-align: center; margin-bottom: 20px; }}
        .nav a {{ color: #2ecc71; text-decoration: none; font-weight: bold; margin: 0 10px; }}
        .nav a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">🏠 Trang chủ</a> | <a href="/sender">📤 ← Sang trang Gửi (Client A)</a>
    </div>
    <h1>📥 Client B - Người Nhận Báo Cáo</h1>
    
    <div class="card">
        <h2>🔓 Tải về & Giải mã</h2>
        <form action="/receive" method="post">
            <label>Nhập Mã Giao Dịch (Transaction ID):</label>
            <input type="text" name="tx_id" placeholder="Ví dụ: TX-A1B2C3" required>
            <br><br>
            <input type="checkbox" name="tamper" value="true"> <i>Giả lập hack/sửa đổi gói tin tại Server</i>
            <br><br>
            <button type="submit">🔓 Tải về & Giải mã</button>
        </form>
    </div>
    
    {receive_result}
    
    <div class="card">
        <h2>📋 Nhật ký hệ thống (Audit Log từ Server)</h2>
        <button onclick="location.reload()" style="background-color: #3498db;">🔄 Cập nhật Log</button>
        <pre>{log_content}</pre>
    </div>
</body>
</html>
"""

async def get_log_content_html():
    log_data = await get_logs()
    return "".join(log_data.get("logs", []))

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML_HOME.format()

@app.get("/sender", response_class=HTMLResponse)
async def sender_page(send_result: str = ""):
    log_content = await get_log_content_html()
    return HTML_SENDER.format(send_result=send_result, log_content=log_content)

@app.get("/receiver", response_class=HTMLResponse)
async def receiver_page(receive_result: str = ""):
    log_content = await get_log_content_html()
    return HTML_RECEIVER.format(receive_result=receive_result, log_content=log_content)

@app.post("/send", response_class=HTMLResponse)
async def send_report(content: str = Form(...)):
    cipher = AES.new(shared_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(content.encode('utf-8'))
    
    tx_id = f"TX-{secrets.token_hex(3).upper()}"
    packet_dict = {
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
    
    with open(f"{tx_id}_encrypted.json", "w", encoding="utf-8") as f:
        json.dump(packet_dict, f, indent=4)
    
    try:
        packet_obj = ReportPacket(**packet_dict)
        await relay_report(packet_obj)
        result_html = f"""<div class='card'><div class='alert success'>
            ✅ Gửi thành công!<br>
            <b>Mã giao dịch (TX ID):</b> <span style='color:blue; font-size:18px;'>{tx_id}</span><br>
            <small>Bản mã gửi đi: {ciphertext.hex()[:30]}...</small>
        </div></div>"""
    except HTTPException as e:
        result_html = f"<div class='card'><div class='alert danger'>❌ Server từ chối: {e.detail}</div></div>"
    except Exception as e:
        result_html = f"<div class='card'><div class='alert danger'>❌ Lỗi hệ thống: {e}</div></div>"
        
    log_content = await get_log_content_html()
    return HTML_SENDER.format(send_result=result_html, log_content=log_content)

@app.post("/send_file", response_class=HTMLResponse)
async def send_file_client(file: UploadFile = File(...)):
    file_bytes = await file.read()
    
    cipher = AES.new(shared_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_bytes)
    
    tx_id = f"TX-{secrets.token_hex(3).upper()}"
    packet_dict = {
        "transaction_id": tx_id,
        "session_id": "SS-WEB-101",
        "timestamp": int(time.time()),
        "nonce": secrets.token_hex(5),
        "sender_id": "Client_A",
        "receiver_id": "Client_B",
        "data_type": "file",
        "file_name": file.filename,
        "encrypted_data": {
            "ciphertext": ciphertext.hex(),
            "iv": cipher.nonce.hex(),
            "tag": tag.hex()
        }
    }
    
    with open(f"{tx_id}_encrypted.json", "w", encoding="utf-8") as f:
        json.dump(packet_dict, f, indent=4)
    
    try:
        packet_obj = ReportPacket(**packet_dict)
        await relay_report(packet_obj)
        result_html = f"""<div class='card'><div class='alert success'>
            ✅ Gửi file thành công!<br>
            <b>Tên file:</b> {file.filename}<br>
            <b>Kích thước gốc:</b> {len(file_bytes)} bytes<br>
            <b>Mã giao dịch (TX ID):</b> <span style='color:blue; font-size:18px;'>{tx_id}</span><br>
            <small>Bản mã gửi đi: {ciphertext.hex()[:30]}...</small>
        </div></div>"""
    except HTTPException as e:
        result_html = f"<div class='card'><div class='alert danger'>❌ Server từ chối: {e.detail}</div></div>"
    except Exception as e:
        result_html = f"<div class='card'><div class='alert danger'>❌ Lỗi hệ thống: {e}</div></div>"
    
    log_content = await get_log_content_html()
    return HTML_SENDER.format(send_result=result_html, log_content=log_content)

@app.post("/receive", response_class=HTMLResponse)
async def receive_report(tx_id: str = Form(...), tamper: str = Form(None)):
    try:
        packet = await get_report(tx_id)
        enc_data = packet["encrypted_data"]
        
        ciphertext_bytes = bytes.fromhex(enc_data["ciphertext"])
        iv_bytes = bytes.fromhex(enc_data["iv"])
        tag_bytes = bytes.fromhex(enc_data["tag"])
        
        if tamper == "true":
            ciphertext_bytes = ciphertext_bytes[:-1] + b'\x00'
            
        cipher = AES.new(shared_key, AES.MODE_GCM, nonce=iv_bytes)
        decrypted_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
        
        data_type = packet.get("data_type", "text")
        if data_type == "file":
            file_name = packet.get("file_name", "file_khong_ten")
            result_html = f"""<div class='card'><div class='alert success'>
                🔒 Xác thực E2EE thành công!<br>
                <b>Tên file gốc:</b> {file_name}<br>
                <b>Kích thước:</b> {len(decrypted_bytes)} bytes<br>
                <a href='/download/{tx_id}' style='display:inline-block; margin-top:10px; padding:10px 20px; background-color:#27ae60; color:white; text-decoration:none; border-radius:4px; font-weight:bold; font-size:16px;'>⬇ Tải file đã giải mã về máy</a>
            </div></div>"""
        else:
            plaintext = decrypted_bytes.decode('utf-8')
            result_html = f"""<div class='card'><div class='alert success'>
                🔒 Xác thực E2EE thành công!<br>
                <b>Nội dung giải mã:</b> <span style='color:green;'>{plaintext}</span>
            </div></div>"""
    except HTTPException:
        result_html = "<div class='card'><div class='alert danger'>❌ Không tìm thấy TX ID này trên Server!</div></div>"
    except ValueError:
        result_html = """<div class='card'><div class='alert danger'>
            🚨 DỮ LIỆU BỊ TAMPER/SỬA ĐỔI!<br>
            Hệ thống phát hiện lỗi sai lệch mã băm kiểm tra toàn vẹn (AES-GCM Auth Tag thất bại). Từ chối giải mã!
        </div></div>"""
    except Exception as e:
        result_html = f"<div class='card'><div class='alert danger'>❌ Lỗi: {e}</div></div>"
        
    log_content = await get_log_content_html()
    return HTML_RECEIVER.format(receive_result=result_html, log_content=log_content)

@app.get("/download/{tx_id}")
async def download_file(tx_id: str):
    try:
        packet = await get_report(tx_id)
        enc_data = packet["encrypted_data"]
        
        ciphertext_bytes = bytes.fromhex(enc_data["ciphertext"])
        iv_bytes = bytes.fromhex(enc_data["iv"])
        tag_bytes = bytes.fromhex(enc_data["tag"])
        
        cipher = AES.new(shared_key, AES.MODE_GCM, nonce=iv_bytes)
        file_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
        
        file_name = packet.get("file_name", "downloaded_file")
        
        return Response(
            content=file_bytes,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{file_name}"'}
        )
    except HTTPException:
        return HTMLResponse("<h1>❌ Không tìm thấy TX ID này!</h1>")
    except ValueError:
        return HTMLResponse("<h1>🚨 DỮ LIỆU BỊ TAMPER! Từ chối giải mã file.</h1>")
    except Exception as e:
        return HTMLResponse(f"<h1>❌ Lỗi: {e}</h1>")

if __name__ == "__main__":
    import uvicorn
    print("===================================================")
    print("Dang khoi dong He Thong E2EE BTL2222 (Single File)...")
    print("Vui long truy cap vao: http://127.0.0.1:8000")
    print("===================================================")
    uvicorn.run(app, host="127.0.0.1", port=8000)
