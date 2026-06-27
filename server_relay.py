from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import time

app = FastAPI(title="Zero-Knowledge Relay Server")

USED_NONCES = set()
LOG_FILE = "server.log"
DB_REPORTS = {} # Lưu tạm gói tin trong bộ nhớ (Key: transaction_id)

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

def write_audit_log(level, tx_id, session_id, message):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{level}] [TX: {tx_id}] [Session: {session_id}] {message}\n"
    print(log_entry.strip())
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)

@app.post("/relay")
async def relay_report(packet: ReportPacket):
    current_time = int(time.time())
    
    # 1. Kiểm tra hết hạn timestamp (5 phút)
    if abs(current_time - packet.timestamp) > 300:
        write_audit_log("WARN", packet.transaction_id, packet.session_id, "Từ chối: Timestamp quá hạn.")
        raise HTTPException(status_code=400, detail="Timestamp expired")
        
    # 2. Kiểm tra Replay Attack
    if packet.nonce in USED_NONCES:
        write_audit_log("CRITICAL", packet.transaction_id, packet.session_id, f"Phát hiện REPLAY ATTACK! Nonce '{packet.nonce}' đã dùng.")
        raise HTTPException(status_code=400, detail="Replay Attack Detected")
        
    USED_NONCES.add(packet.nonce)
    
    # 3. Lưu gói tin mã hóa vào "tổng đài" trung gian
    DB_REPORTS[packet.transaction_id] = packet.dict()
    
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)