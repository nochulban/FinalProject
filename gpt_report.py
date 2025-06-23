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


# ------------------ GPT로 개요+요약 생성 ------------------

def get_summary_from_gpt(keyword, key, nudeDF, normalCount, malwareDF):
    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {key}"
    }
    prompt = (
    "당신은 클라우드 보안 탐지 보고서를 작성하는 AI입니다.\n"
    "이 보고서는 공개된 오브젝트 스토리지(S3/NCP 등)에서 수집한 문서들의 메타데이터를 기반으로 자동 생성됩니다.\n"
    "보고서에는 유출 의심 문서 정보뿐만 아니라, 해당 파일에 대한 VirusTotal 기반 악성코드 탐지 결과도 포함됩니다.\n"
    "아래 데이터프레임은 URL, 확장자, 수집일, 소속 버킷, VirusTotal 탐지 수 등으로 구성된 메타데이터입니다.\n"
    f"{malwareDF} 가 empty 이면 악성코드 탐지 요약에는 악성코드가 없다고 적어주면 됩니다."
    "결론 및 권고사항 에는 아래의 내용을 포함하는 내용을 포함하여야합니다." 
    "탐지된 문서들 중 일부는 악성코드로 분류되었으며, 외부에 민감 정보가 노출되었을 가능성과 함께 시스템 침투 가능성도 존재합니다.\n"
    "- 공개 버킷 설정 여부 검토 및 비공개 전환\n"
    "- 문서 내 포함된 정보의 민감도 및 악성여부 분석\n"
    "- VirusTotal 및 백신 탐지 결과 기반 경고 대응 체계 구축\n"
    "- 자동 점검 시스템의 주기적 실행 도입\n"
    "- 악성코드의 내용이 없을 경우 안전하다는 내용 도입\n"
    
"\n"
"위의 프롬프트를 참고 하여 다음 형식으로 보고서를 작성하십시오. 형식은 마크다운이 아닌 **텍스트 기반(plain text)**입니다.\n"
"\n"
"==============================\n"
    "공개 S3 버킷 대상 유출 및 악성코드 탐지 보고서\n"
    "==============================\n"
    "\n"
    "[보고서 개요]\n"
    f"검색 키워드 '{keyword}'를 기반으로 자동화된 보안 점검 시스템을 통해 공개 오브젝트 스토리지 내에서 수집된 유출 의심 파일들을 분석하였습니다. 본 보고서는 수집 대상의 기본 정보, 수집 방식, 탐지 결과를 포함하며, 특히 수집된 문서에 대해 VirusTotal 기반 악성코드 유무를 진단하고 그 결과를 함께 제공합니다.\n"
    "\n"
    f"[탐지 요약]\n"
    f"- 해당 키워드로 탐지 한 파일 수: {nudeDF['file_count'].sum()}\n"
    f"- 공개 버킷 수: {nudeDF.groupby('bucket_url').count()}\n"
    "- 해당 키워드로 가져온 버킷 내의 악성 파일 수: {malicious_count}\n"
    f"- 해당 키워드로 가져온 버킷 내의 정상 파일 수: {normalCount}\n"
    "\n"
    "[키워드와 관련된 버킷 내 문서 상세 리스트]\n"
    "각 항목은 한 줄씩 구분하여 다음 형식으로 나열:\n"
    "  URL: {bucket_url}\n"
    "  파일수: {file_count}\n"
    "  수집일: {dt}\n"
    "\n"
    "[악성코드 탐지 요약]\n"
    "각 악성 문서는 다음과 같은 형식으로 나열합니다:\n"
    "  파일명: {filename}\n"
    "  URL: {url}\n"
    "  확장자: {extension}\n"
    "  VirusTotal 탐지 수: {malicious_count}\n"
    "  탐지일: {detected_at}\n"
    
    f"유출된 버킷 관련 데이터:\n{nudeDF}"
    f"유출된 버킷 안의 정상 데이터 카운트 :\n{normalCount}"
    f"유출된 버킷 안의 악성 데이터 내용 :\n{malwareDF}"
    "\n"
    "[결론 및 권고사항]\n"
    "\n"
    "\n"

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

    # 개요 및 탐지 요약
    pdf.multi_cell(0, 10, "1. 보고서 개요 및 탐지 요약")
    pdf.set_font("NanumGothic", size=12)
    for line in summary_text.split('\n'):
        pdf.multi_cell(0, 10, line)

    # 유출 문서 리스트
    # pdf.ln(5)
    # pdf.set_font("NanumGothic", size=14)
    # pdf.multi_cell(0, 10, "2. 유출 문서 리스트")
    # pdf.set_font("NanumGothic", size=12)

    if 'file_name' in df.columns and 'bucket_url' in df.columns:
        bucket_count = df['bucket_url'].nunique()
        file_count = df[''].nunique()
        pdf.multi_cell(0, 10, f"탐지된 전체 버킷 수: {bucket_count}개")
        pdf.multi_cell(0, 10, f"탐지된 전체 파일 수: {file_count}개")
        pdf.ln(5)

        grouped = df.groupby('bucket_url')
        for bucket, group in grouped:
            pdf.ln(4)
            pdf.set_font("NanumGothic", size=12)
            pdf.multi_cell(0, 8, f"[버킷 주소] {bucket}")
            for idx, row in group.iterrows():
                filename = str(row.get('file_name', '파일명 없음'))
                #extension = str(row.get('extension', '확장자 없음'))
                file_count = str(row.get('file_count', '확장자 없음'))
                #file_size = str(row.get('file_size', '크기 정보 없음'))
                pdf.multi_cell(0, 8, f"- {filename}, {file_count} ")
    else:
        print("파일명 또는 버킷 주소 정보 없음")

    pdf.output(pdf_path, "F")

# ------------------ 전체 파이프라인 실행 ------------------

def run_pipeline(keyword):
    nudeDF, normalCount, malwareDF = load_mysql_table_to_dataframe()
    
    sample = nudeDF.head(5).to_string(index=False)
    print(nudeDF)
    print(normalCount)
    print(malwareDF)

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
