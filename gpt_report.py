import pandas as pd
import requests
import pymysql
import connectDatabase
from fpdf import FPDF
import os
from datetime import datetime
from dotenv import load_dotenv
os.chdir(os.path.dirname(os.path.abspath(__file__)))


load_dotenv()
api_key = os.getenv('OPENAPI_KEY')   # 👉 OpenAI API 키 입력
malicious_count = 0

# ------------------ GPT로 개요+요약 생성 ------------------

def get_summary_from_gpt(keyword, key, nudeDF, normalCount, malwareDF):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}"
    }

    # 중복 제거된 버킷 URL 목록 문자열 생성
    unique_buckets = nudeDF['bucket_url'].dropna().unique()
    bucket_list_str = "\n".join(f"- {url}" for url in sorted(unique_buckets))

    prompt = (
        "당신은 클라우드 보안 전문가이며, 아래 데이터는 공개 오브젝트 스토리지에서 수집한 문서들의 메타데이터입니다.\n"
        f"이번 보고서는 키워드 '{keyword}'로 수집된 결과를 기반으로 작성됩니다.\n"
        "이 데이터를 기반으로 보고서를 작성해 주세요.\n"
        "\n"
        "보고서는 다음 형식으로 구성되어야 하며, 특히 '결론 및 권고사항'은 실제 데이터 상태에 따라 유연하게 작성되어야 합니다:\n"
        "\n"
        "1. [보고서 개요] - 어떤 키워드로 수집되었고, 어떤 파일들이 탐지되었는지 요약\n"
        "2. [탐지 요약] - 총 수집 파일 수, 공개 버킷 수, 악성 파일 수, 정상 파일 수\n"
        "3. [수집된 공개 버킷 URL 목록] - 중복되지 않은 공개 bucket_url 항목을 한 줄에 하나씩 나열\n"
        "4. [악성코드 탐지 요약] - 악성코드 탐지 여부에 따라 유무를 요약, 탐지되었을 경우 목록화\n"
        "5. [결론 및 권고사항] - 아래 기준에 따라 실제 상황을 분석하여 문장을 구성하세요:\n"
        "\n"
        "  - 만약 악성코드가 전혀 탐지되지 않은 경우:\n"
        "    > 현재까지는 위험 징후는 없지만, 공개 설정된 버킷을 통한 정보 유출 가능성은 상존하므로 주의가 필요합니다.\n"
        "  - 악성코드가 탐지된 경우:\n"
        "    > 외부 노출된 문서 일부에서 악성코드가 확인되었습니다. 시스템 침해 가능성 및 정보 유출 우려가 있으므로 즉각적인 조치가 필요합니다.\n"
        "  - 모든 보고서에서 공통적으로 아래 권고사항 중 필요한 항목을 판단하여 포함시켜야 합니다 (필요한 것만 사용):\n"
        "    - 공개 버킷 설정 여부 점검 및 비공개 전환 조치\n"
        "    - 문서 내 포함된 정보의 민감도 분석\n"
        "    - VirusTotal 및 보안 솔루션 연계 점검 체계 수립\n"
        "    - 주기적 자동 점검 시스템 도입\n"
        "    - 탐지 문서에 대한 로그 기록 및 보존\n"
        "\n"
        "다음은 분석에 사용할 데이터입니다:\n"
        "=== 수집된 파일 메타데이터 ===\n"
        f"{nudeDF.to_string(index=False)}\n\n"
        "=== 정상 파일 수 ===\n"
        f"{normalCount}\n\n"
        "=== 악성코드 탐지 목록 ===\n"
        f"{malwareDF.to_string(index=False)}\n\n"
        f"=== 수집된 공개 버킷 URL 목록 ===\n{bucket_list_str}\n\n"
        "==============================\n"
        "공개 S3 버킷 대상 유출 및 악성코드 탐지 보고서\n"
        "==============================\n"
        "[보고서 개요]\n(작성)\n\n"
        "[탐지 요약]\n(작성)\n\n"
        "[수집된 공개 버킷 URL 목록]\n(작성)\n\n"
        "[악성코드 탐지 요약]\n(작성)\n\n"
        "[결론 및 권고사항]\n(작성)"
    )

    data = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
        "max_tokens": 2048
    }

    response = requests.post(url, headers=headers, json=data, timeout=200)
    response.raise_for_status()
    result = response.json()
    return result['choices'][0]['message']['content']

# ------------------ MySQL 연결 및 데이터 가져오기 ------------------

def load_mysql_table_to_dataframe():

    rows = connectDatabase.setDataFrame()
    normalCount = connectDatabase.setNormalCount()
    malwareRows = connectDatabase.setMaldocDataFrame()
    
    df = pd.DataFrame(rows)
    malwareDF = pd.DataFrame(malwareRows)
    return df, normalCount, malwareDF

# ------------------ PDF 보고서 저장 ------------------

def save_report_to_pdf(pdf_path, summary_text, df):
    pdf = FPDF(orientation='P', unit='mm', format='A4')
    pdf.add_page()
    pdf.add_font("NanumGothic", '', "NanumGothic.ttf", uni=True)
    pdf.set_font("NanumGothic", size=14)

    # 보고서 요약
    pdf.multi_cell(0, 10, "1. 보고서 개요 및 탐지 요약")
    pdf.set_font("NanumGothic", size=12)
    for line in summary_text.split('\n'):
        pdf.multi_cell(0, 10, line)

    # 블러 처리 이미지 삽입
    pdf.add_page()
    pdf.set_font("NanumGothic", size=14)
    pdf.multi_cell(0, 10, "2. 블러 처리된 민감 이미지 예시")

    image_folder = "/Users/leejaeyoon/opt/isolation"
    image_files = []
    for root, dirs, files in os.walk(image_folder):
        for file in files:
            if file.endswith('.png') and 'blurred' in file:
                image_files.append(os.path.join(root, file))
    image_files.sort()

    if not image_files:
        pdf.multi_cell(0, 10, "※ 블러 처리된 이미지를 찾을 수 없습니다.")
    else:
        for img_path in image_files:
            pdf.ln(5)
            try:
                pdf.image(img_path, w=180)
            except RuntimeError:
                pdf.multi_cell(0, 10, f"[오류] 이미지를 추가할 수 없습니다: {img_path}")

    pdf.output(pdf_path, "F")

# ------------------ 전체 파이프라인 실행 ------------------

def run_pipeline(keyword):
    rows = connectDatabase.setDataFrame()
    normalCount = connectDatabase.setNormalCount()
    malwareRows = connectDatabase.setMaldocDataFrame()

    nudeDF = pd.DataFrame(rows)
    malwareDF = pd.DataFrame(malwareRows)

    summary_text = get_summary_from_gpt(keyword, api_key, nudeDF, normalCount, malwareDF)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = f"report_{timestamp}.pdf"

    save_report_to_pdf(pdf_path, summary_text, nudeDF)
    print(f"✅ PDF 보고서가 생성되었습니다: {pdf_path}")

    #connectDatabase.truncateBucketTable()
    #connectDatabase.truncateDocumentsTable()

# ------------------ 메인 실행 ------------------

#if __name__ == "__main__":
    
    ## 저장할 파일 경로 설정
    ##ppt_save_path = "bucket_report.pptx"
    ##docx_save_path = "bucket_report.docx"    

    # 테스트시 주석 해제 
    # keyword = input()
    # run_pipeline(keyword)
