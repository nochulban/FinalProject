import requests
import hashlib
import paramiko
import os
import time
import connectDatabase
import yara
from dotenv import load_dotenv

#######################
######################
#VirusTotal



load_dotenv()
API_KEY = os.getenv('VIRUSTOTAL_API')


# SHA-256 해시 계산
def getFileHash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b''):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# 해시 기반 분석 결과 조회
def useVirusTotal(file_url, file_name, file_hash, extension):
    isNormal = True        
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {
        'x-apikey': API_KEY,
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        malicious = stats['malicious']
        suspicious = stats['suspicious']
        harmless = stats['harmless']
        undetected = stats['undetected']

        print(f"[+] 해시 분석 결과")
        print(f"  - Malicious : {malicious}")
        print(f"  - Suspicious: {suspicious}")
        print(f"  - Harmless  : {harmless}")
        print(f"  - Undetected: {undetected}")

        if malicious > 0 or suspicious > 0:
            isNormal = False
            print("⚠️  이 파일은 악성일 수 있습니다.")
            connectDatabase.classificationFile(isNormal, file_url, file_name ,file_hash, extension, malicious, suspicious )
        else:
            print("✅ 이 파일은 안전해 보입니다.")
            #connectDatabase.classificationFile(isNormal, file_url, file_name ,file_hash, extension,0 ,0)
    elif response.status_code == 404:
        print("❌ 해당 파일 해시는 VirusTotal에 존재하지 않습니다. 파일을 직접 업로드해야 합니다.")
        #connectDatabase.classificationFile(isNormal, file_url, file_name ,file_hash, extension,0, 0)
    else:
        print("[!] 해시 조회 실패:", response.text)


def scanVirusTotalDirectory(directory):
    count = 0
    total_duration = 0
    request_count = 0

    for root, _, files in os.walk(directory):
        for file in files:
            if file == '.DS_Store':
                continue

            file_path = os.path.join(root, file)
            try:                
                if count == 10:
                    print('🔁 10회차 요청 제한 - 스캔 종료')
                    break

                url = root.split('isolation/')[1]
                extension = file.split('.')[-1]
                file_hash = getFileHash(file_path)

                print(f"\n🔍 [파일 분석 시작] {file} ({file_hash})")
                start_time = time.time()
                useVirusTotal(url, file, file_hash, extension)
                end_time = time.time()

                duration = end_time - start_time
                total_duration += duration
                request_count += 1
                count += 1

                print(f"⏱️ 분석 시간: {duration:.2f}초")

            except Exception as e:
                print(f"[!] 파일 처리 중 오류 발생: {file_path} - {str(e)}")

    if request_count > 0:
        avg_time = total_duration / request_count
    else:
        avg_time = 0

    print("\n📊 [VirusTotal 스캔 요약]")
    print(f"🔢 총 요청 수: {request_count}")
    print(f"⏱️ 총 소요 시간: {total_duration:.2f}초")
    print(f"📈 평균 분석 시간: {avg_time:.2f}초")

##################
##################
#YARA

# 확장자별 룰셋 매핑
YARA_RULES_MAP = {
    '.doc': 'yara/doc_rules.yar',
    '.docx': 'yara/doc_rules.yar',
    '.hwp': 'yara/hwp_rules.yar',
    '.pdf': 'yara/pdf_rules.yar',
    '.txt': 'yara/txt_rules.yar',
    '.xls': 'yara/xls_rules.yar',
    '.xlsx': 'yara/xls_rules.yar',
    # 지금 csv가 없음
}

def useYara(rootPath :str, filePath: str, fileUrl: str, fileName: str, fileHash: str, extension:str ) -> list:
    ext = os.path.splitext(filePath)[-1].lower()
    rule_path = YARA_RULES_MAP.get(ext)
    
    if rule_path and os.path.exists(rule_path):
        try:
            isNormal = True
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(filepath=filePath)
            if matches:
                rule_names = [match.rule for match in matches]
                print(f"{os.path.basename(filePath)} - 감지된 바이러스 룰: {', '.join(rule_names)}")
                connectDatabase.classificationFile(isNormal, fileUrl, fileName ,fileHash, extension, 0, 0, 'O', rule_names)
                return rule_names
            else:
                print(f"{os.path.basename(filePath)} - 바이러스 없음")
                isNormal = True
                connectDatabase.classificationFile(isNormal, fileUrl, fileName ,fileHash, extension, 0, 0)
                sendFileMainSFTP(rootPath, filePath)
                print(f"{os.path.basename(filePath)} - 메인서버 전송 완료")
                return []
        except Exception as e:
            print(f"[!] 오류 - {filePath}: {e}")
            return []
    else:
        print(f"{os.path.basename(filePath)} - 룰 없음 또는 확장자 미지원")
        return []


def scanDirectoryYara(root_dir: str) -> dict:
    result = {}
    total_duration = 0
    request_count = 0

    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)

            try:
                fileUrl = root.split('isolation/')[1]
                extension = file.split('.')[-1]
                fileHash = getFileHash(file_path)

                print(f"\n🔍 [YARA 검사 시작] {file}")

                start_time = time.time()
                matched_rules = useYara(root_dir, file_path, fileUrl, extension, fileHash, extension)
                end_time = time.time()

                duration = end_time - start_time
                total_duration += duration
                request_count += 1

                print(f"⏱️ 검사 시간: {duration:.2f}초")

                if matched_rules:
                    result[file_path] = matched_rules

            except Exception as e:
                print(f"[!] 오류 발생 - {file_path}: {str(e)}")

    # 통계 출력
    if request_count > 0:
        avg_time = total_duration / request_count
    else:
        avg_time = 0

    print("\n📊 [YARA 검사 요약]")
    print(f"🔢 총 검사 파일 수: {request_count}")
    print(f"⏱️ 총 소요 시간: {total_duration:.2f}초")
    print(f"📈 평균 검사 시간: {avg_time:.2f}초")

    return result



####################
####################
#file FTP download -> main
def sendFileMainSFTP(mainroot, filePath):
    try:
        #print(f'{mainID}')

        transport = paramiko.Transport((os.getenv('MAIN_IP'), 22))
        transport.connect(username=os.getenv('MAIN_ID'), password=os.getenv('MAIN_PASSWORD'))
        sftp = paramiko.SFTPClient.from_transport(transport)

        remote_path = f'{mainroot}' + '/' +os.path.basename(filePath)
        print(f'{remote_path}')
        sftp.put(filePath, remote_path)

        sftp.close()
        transport.close()
        print('파일전송 완료')

    except Exception as e:
        print(f'에러 발생: {e}')


def main(mainroot):
    scanVirusTotalDirectory(mainroot)
    scanDirectoryYara(mainroot)

            

# if __name__ == '__main__':

#     mainroot = '/opt/isolation'
#     scanVirusTotalDirectory(mainroot)
#     scanDirectoryYara(mainroot)

