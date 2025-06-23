from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from dotenv import load_dotenv
import crawler
import requests
import ocrProcess
import gpt_report
import os

load_dotenv()

app = FastAPI()
mainroot = '/opt/isolation'
DOWNLOAD_SERVER_URL= f"http://{os.getenv('DOWNLOAD_IP')}:8001/start-download"

class KeywordRequest(BaseModel):
    keyword: str

@app.post("/process")
def process_keyword(req: KeywordRequest):
    keyword = req.keyword.strip()

    try:
        print(f"[1차 시작] keyword = '{keyword}'")
        if keyword == '':
            crawler.pageSelenium(keyword)
        else:
            crawler.grayhatApi(keyword)
            crawler.pageSelenium(keyword)

        print("[1차 완료] DB 저장 중")
        crawler.crawledPageDataInsert()

        # 2차 처리 요청
        download_url = DOWNLOAD_SERVER_URL
        print(f"[2차 요청] URL = {download_url}")
        
        response = requests.post(download_url, json={"keyword": keyword})
        print(f"[2차 응답] status = {response.status_code}, text = {response.text}")

        if response.status_code != 200:
            raise Exception(f"Download server error: {response.text}")

        return {"status": "started", "message": "1차 완료, 2차 처리 요청됨", "keyword": keyword}

    except Exception as e:
        import traceback
        print("❌ 예외 발생:")
        print(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))
    

@app.post("/notify")
async def notify_2nd_step_done(req: Request):
    body = await req.json()
    keyword = body.get("keyword")

    try:
        # 3차: OCR 및 GPT 보고서 처리
        ocrProcess.main(mainroot)
        gpt_report.run_pipeline(keyword)

        return {"status": "success", "message": f"3차 처리 완료 for {keyword}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


    
