import yara
import ftplib
import os
import paramiko
from dotenv import load_dotenv

load_dotenv()

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

def scan_file_with_yara(file_path: str) -> list:
    ext = os.path.splitext(file_path)[-1].lower()
    rule_path = YARA_RULES_MAP.get(ext)
    
    if rule_path and os.path.exists(rule_path):
        try:
            rules = yara.compile(filepath=rule_path)
            matches = rules.match(filepath=file_path)
            if matches:
                rule_names = [match.rule for match in matches]
                print(f"{os.path.basename(file_path)} - 감지된 바이러스 룰: {', '.join(rule_names)}")
                return rule_names
            else:
                print(f"{os.path.basename(file_path)} - 바이러스 없음")
                sendFileMainSFTP(file_path)
                return []
        except Exception as e:
            print(f"[!] 오류 - {file_path}: {e}")
            return []
    else:
        print(f"{os.path.basename(file_path)} - 룰 없음 또는 확장자 미지원")
        return []


def scan_directory(root_dir: str) -> dict:
    result = {}
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_path = os.path.join(root, file)
            matched_rules = scan_file_with_yara(file_path)
            if matched_rules:
                result[file_path] = matched_rules
    return result


#file FTP download -> main
def sendFileMain(filePath):
    try:
        session = ftplib.FTP()
        session.connect(os.getenv('MAIN_IP'), 21) # 두 번째 인자는 port number
        session.login(os.getenv('MAIN_ID'), os.getenv('MAIN_PASSWORD'))   # FTP 서버에 접속
    
        #uploadfile = open('./파일경로/화난무민.jpg' ,mode='rb') #업로드할 파일 open
        uploadfile = open(f'{filePath}' ,mode='rb') #업로드할 파일 open
    
        session.encoding='utf-8'
        #session.storbinary('STOR ' + '/img/CodingMooMin.jpg', uploadfile) #파일 업로드
        session.storbinary('/opt/isolation', uploadfile) #파일 업로드
        
        uploadfile.close() # 파일 닫기
        
        session.quit() # 서버 나가기
        print('파일전송 완료')
    except Exception as e:
        print(f'에러발생 + {e}')


def sendFileMainSFTP(filePath):
    try:
        transport = paramiko.Transport((os.getenv('MAIN_IP'), 22))
        transport.connect(username=os.getenv('MAIN_ID'), password=os.getenv('MAIN_PASSWORD'))
        sftp = paramiko.SFTPClient.from_transport(transport)

        remote_path = '/opt/isolation/' + os.path.basename(filePath)
        sftp.put(filePath, remote_path)

        sftp.close()
        transport.close()
        print('파일전송 완료')
    except Exception as e:
        print(f'에러 발생: {e}')


# 메인 실행 예시
if __name__ == "__main__":
    #target_dir = "/opt/isolation"
    target_dir = '/Users/leejaeyoon/opt/isolation'
    detections = scan_directory(target_dir)

    print("==== YARA 탐지 결과 ====")
    for path, rules in detections.items():
        print(f"[+] {path} → {rules}")