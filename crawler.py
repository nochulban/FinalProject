import connectDatabase
import os
import boto3
import http.client
import json
import time
import requests
import tor_contorller
from dotenv import load_dotenv
from selenium.webdriver.common.by import By
from datetime import datetime
from urllib.parse import quote
from hashlib import sha256
from datetime import datetime
from botocore.exceptions import ClientError


# 허용된 확장자 목록
allowed_extensions = {'txt', 'hwp', 'jpg', 'png', 'ppt', 'xlsx', 'pdf', 'csv'}
load_dotenv()
torPassword = os.getenv('TOR_PASSWORD')

#grayhatAPI
def grayhatApi(keyword):
    # 연결 설정
    conn = http.client.HTTPSConnection("buckets.grayhatwarfare.com")

    headers = {
    'Authorization': f"Bearer {os.getenv('GRAYHAT_API_KEY')}"
    }
    
    encoded_keyword = quote(keyword)

    # 공식 문서 기반 요청 경로 (파일 키워드 + full path )
    conn.request("GET", f"/api/v2/files?keywords={encoded_keyword}&full-path=1", headers=headers)


    res = conn.getresponse()
    data = res.read()

    try:
        # JSON 파싱
        result = json.loads(data.decode("utf-8"))
        files = result.get("files", [])

        if not files:
            print("[-] 검색한 키워드의 버킷이 없습니다.")
        else:
            # 중복 제거용 버킷 저장 Set
            bucket_file_counts = {}

            print("[+] 검색한 키워드의 버킷 목록:")
            for i, file in enumerate(files, 1):
                bucket = file.get("bucket")
                if bucket and (".s3." in bucket or "s3-" in bucket or "amazonaws.com" in bucket):
                    # 버킷별 파일 카운트 저장
                    if bucket in bucket_file_counts:
                        bucket_file_counts[bucket] += 1
                    else:
                        bucket_file_counts[bucket] = 1
            
            #
            for idx, bucket in enumerate(bucket_file_counts.keys(), 1):
                print(f"[{idx}] {bucket} - 총 파일 수: {bucket_file_counts[bucket]}")

                httpsName = f"https://{bucket}"
                print(f"✅ Test {httpsName}")

                try:
                    existsBucket = connectDatabase.repeatCheck(httpsName)     
                    if existsBucket > 0:
                        print(f"⚠️ 중복된 항목 (이미 존재): {httpsName}")
                        continue
                except Exception as e:
                    print("중복 체크 에러:", e)
                    continue

                #연결확인 후 Insert
                try:        
                    getHeaders = {"User-Agent": "Mozilla/5.0"} 
                    response = requests.get(httpsName, headers=getHeaders, timeout=8, stream=True, verify=False)        

                    if response.status_code == 200: #정상 Insert
                        print(f"✅ 연결 가능: {httpsName}")                        
                        connectDatabase.bucketUrlInsert(response.status_code, bucket_file_counts[bucket], httpsName)
                        
                    else:                          #에러 Insert
                        print(f"✅ 연결 불가: {httpsName}")
                        connectDatabase.bucketUrlInsert(response.status_code, bucket_file_counts[bucket], httpsName)

                    print(f"🪣 {bucket} | 📂 파일 수: {bucket_file_counts[bucket]} | 🔗 {httpsName}")
                except Exception as e:
                    print(f"❌ 페이지 {httpsName} 접속 확인 중 오류 발생: {e}")

    except Exception as e:
        print(f"[!] 오류 발생: {e}")
        print(data.decode("utf-8"))



#grayhatPageSelenium
def pageSelenium(keyword):
    # # Chrome 옵션 설정 (Windows에서도 헤드리스로 작동)
    # options = Options()
    # options.add_argument("--headless=new")  # 최신 방식의 헤드리스 모드
    # options.add_argument("--disable-gpu")
    # options.add_argument("--window-size=1920,1080")


    # # 크롬 드라이버 실행
    # driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
    # options = webdriver.ChromeOptions()
    # options.add_experimental_option("excludeSwitches", ["enable-logging"])
    headers = {"User-Agent": "Mozilla/5.0"}  # 요청 차단 우회용 헤더
    # #browser = webdriver.Chrome(options=options)


    page = 1
    print(f"\n[📄 GrayhatWarfare 버킷 목록 크롤링 시작]\n")

    while True:
        print(f"📄 페이지 {page} ------------------------------")
        password = 'spzmfzoa2025!@#'
        tor_contorller.renewTorIP(password)
        time.sleep(10)
        driver = tor_contorller.create_tor_driver()
        tor_contorller.getCurrentIP()

        if keyword == '':
            base_url = "https://buckets.grayhatwarfare.com/buckets?type=aws&page=" + str(page)

        else:
            encoded_keyword = quote(keyword)
            base_url = f"https://buckets.grayhatwarfare.com/buckets?keywords={encoded_keyword}type=aws&page=" + str(page)
        driver.get(base_url)
        time.sleep(10)

        try:
            rows = driver.find_elements(By.CSS_SELECTOR, "table.table tbody tr")
            #더이상 크롤링할 데이터가 없을 경우
            if len(rows) == 0:
                print("데이터가 크롤링 되지 않음! 크롤링을 종료합니다.")
                break

            for row in rows:
                cols = row.find_elements(By.TAG_NAME, "td")
                if len(cols) >= 3:
                    name_tag = cols[1].find_element(By.TAG_NAME, "a")
                    count_tag = cols[2].find_element(By.TAG_NAME, "a")

                    name = name_tag.text.strip()
                    count = count_tag.text.strip()
                    url = name_tag.get_attribute("href")

                    httpsName = "https://" + name
                    #print(f"✅ Test {"https://" + name}")

                   
                    
                    #중복체크               
                    try:
                        existsBucket = connectDatabase.repeatCheck(httpsName)     
                        if existsBucket > 0:
                            print(f"⚠️ 중복된 항목 (이미 존재): {httpsName}")
                            continue
                    except Exception as e:
                        print("중복 체크 에러:", e)
                        continue

                    #연결확인 후 Insert
                    try:        
                        response = requests.get(httpsName, headers=headers, timeout=8, stream=True, verify=False)
                        print(f"[{base_url}] 응답 상태 코드: {response.status_code}")

                        if response.status_code == 200: #정상 Insert
                            print(f"✅ 연결 가능: {httpsName}")                        
                            connectDatabase.bucketUrlInsert(response.status_code, count, httpsName)
                            
                        else:                          #에러 Insert
                            print(f"✅ 연결 불가: {httpsName}")
                            connectDatabase.bucketUrlInsert(response.status_code, count, httpsName)

                        print(f"🪣 {name} | 📂 파일 수: {count} | 🔗 {url}")
                    except Exception as e:
                        print(f"❌ 페이지 {httpsName} 접속 확인 중 오류 발생: {e}")
                        
        
        except Exception as e:
            print(f"❌ 페이지 {page} 크롤링 중 오류 발생: {e}")
            
        page += 1
    driver.quit()    
def extract_extension(filename):
    return filename.split('.')[-1] if '.' in filename else ''

#S3접속 후 데이터 추출
def get_s3_file_list(bucket_url):
    try:
        # S3 클라이언트 생성 (AWS 자격 증명 추가)
        s3_client = boto3.client(
            's3',
            aws_access_key_id = os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            region_name=os.getenv("REGION_NAME")
        )

        # S3 버킷 이름 추출
        bucket_name = bucket_url.split('//')[1].split('/')[0].split('.')[0]

        # S3에서 파일 목록 가져오기
        result = s3_client.list_objects_v2(Bucket=bucket_name)

        if 'Contents' in result:
            return [content['Key'] for content in result['Contents']]
        else:
            return []

    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'AccessDenied':
            print(f"❌ 접속이 불가합니다: {bucket_url} (AccessDenied)")
        else:
            print(f"❌ 오류 발생: {bucket_url} ({error_code})")
        return []

    except Exception as e:
        print(f"❌ 예기치 못한 오류: {bucket_url} ({e})")
        return []


def crawledPageDataInsert():
    rows = connectDatabase.getBucketUrl()
    for row in rows:
        bucket_url = row[0]

        # 3. S3에서 파일 목록 가져오기
        file_list = get_s3_file_list(bucket_url)

        for file_name in file_list:
            extension = extract_extension(file_name)

            if extension not in allowed_extensions:
                continue


            #file_hash = sha256(file_name.encode('utf-8')).hexdigest()
            file_hash = '-'
            url = f"{bucket_url}/{file_name}"
            file_size = 0  # 파일 크기는 필요시 S3에서 가져올 수 있음 (파일 정보 추가 가능)

            # 현재 시간을 `date`로 사용
            collected_at = datetime.now()

            data = (
                file_name,
                url,
                extension,
                file_hash,
                collected_at,
                bucket_url,
                file_size
            )
            #connectDatabase.fileRepeatCheck(file_name)
            connectDatabase.insertDocuments(data)

    print("✅ 모든 S3 파일 목록을 documents 테이블에 삽입 완료!")