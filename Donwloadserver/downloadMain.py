from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import os
import requests
import dataDownload
import virusInspection

load_dotenv()
app = FastAPI()

mainroot = '/opt/isolation'
main_server_callback_url = f"http://{os.getenv('MAIN_IP')}:8000/notify"

class KeywordRequest(BaseModel):
    keyword: str

@app.post("/start-download")
def start_download(req: KeywordRequest):
    keyword = req.keyword

    try:            
        print(f"📥 다운로드 요청 받음: {keyword}")
        print(f"🔁 콜백 주소: {main_server_callback_url}")
    # 2차: 다운로드 및 바이러스 검사
        dataDownload.main(mainroot)      
        virusInspection.main(mainroot) 

    # 2차 완료 후 main 서버에 알림
        response = requests.post(main_server_callback_url, json={"keyword": keyword})
        print(f"📡 콜백 응답 코드: {response.status_code}")
        print(f"📡 콜백 응답 내용: {response.text}")
        if response.status_code != 200:
            raise Exception(f"Main server callback failed: {response.text}")

        return {"status": "success", "message": "2차 완료, main 서버에 알림"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


