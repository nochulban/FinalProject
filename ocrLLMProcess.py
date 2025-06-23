import os
import pandas as pd
import uuid
import json
import requests
import infoBlur
import convertDoc
import connectDatabase
import detectUseLLM
from dotenv import load_dotenv
from pdf2image import convert_from_path

load_dotenv()

# ===== 설정 =====
CLOVA_OCR_URL = os.getenv('CLOVERAPI_URL')
CLOVA_OCR_SECRET = os.getenv('CLOVERAPI_KEY')


SUPPORTED_EXTENSIONS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'hwp', 'jpeg', 'png', 'jpg', 'txt']


#텍스트 블러처리
def mask_personal_info(text, sensitive_list):
    for info in sorted(sensitive_list, key=len, reverse=True):
        text = text.replace(info, '*' * len(info))
    return text

#텍스트추출
def extract_text_from_file(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    if ext == '.txt':
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    elif ext == '.csv':
        df = pd.read_csv(file_path, dtype=str)
        return '\n'.join(df.astype(str).apply(lambda row: ' '.join(row), axis=1))
    elif ext == '.xlsx':
        df_list = pd.read_excel(file_path, sheet_name=None, dtype=str)
        all_text = ''
        for sheet_name, df in df_list.items():
            all_text += '\n'.join(df.astype(str).apply(lambda row: ' '.join(row), axis=1)) + "\n"
        return all_text
    else:
        return ""

# ===== OCR 함수 =====
def call_clova_ocr(image_path: str) -> str:
    file_name = os.path.basename(image_path)

    payload = {
        "images": [{"format": "png", "name": "document"}],
        "requestId": str(uuid.uuid4()),
        "version": "V1",
        "timestamp": int(uuid.uuid1().time / 10000)
    }

    with open(image_path, 'rb') as image_file:
        files = {
            'file': (file_name, image_file, 'application/octet-stream'),
            'message': (None, json.dumps(payload), 'application/json')
        }

        headers = {"X-OCR-SECRET": CLOVA_OCR_SECRET}

        print(f"[🔍] CLOVA OCR 요청: {file_name}")
        response = requests.post(CLOVA_OCR_URL, headers=headers, timeout=10, files=files, verify=False)

    if response.status_code == 200:
        result_json = response.json()
        #print(result_json)
        fields = result_json['images'][0].get('fields', [])
        texts = [field['inferText'] for field in fields]
        full_text = '\n'.join(texts)
        return full_text, fields
    else:
        print(f"[❌] OCR 실패: {response.status_code} - {response.text}")
        return ""

def ocr_documents(MAIN_DIR):
    # 먼저 루트 디렉토리의 텍스트 파일 처리
    print(f"[📁] 루트 디렉토리 텍스트 파일 처리 중: {MAIN_DIR}")
    text_files = sorted([
        f for f in os.listdir(MAIN_DIR)
        if f.endswith(('.txt', '.csv', '.xlsx')) and os.path.isfile(os.path.join(MAIN_DIR, f))
    ])

    for txt_file in text_files:
        txt_path = os.path.join(MAIN_DIR, txt_file)
        extracted_text = extract_text_from_file(txt_path)

        # 개인정보 탐지
        pii_data = detectUseLLM.detect_pii_with_ollama(extracted_text)

        found_info = []
        for values in pii_data.values():
            found_info.extend(values)

        if found_info:
            info_path = os.path.join(MAIN_DIR, f"{txt_file}_detected_info.txt")
            with open(info_path, 'w', encoding='utf-8') as f:
                for item in found_info:
                    f.write(item + "\n")
            print(f"[🔐] 루트 개인정보 {len(found_info)}건 저장 완료: {info_path}")

            masked_text = mask_personal_info(extracted_text, found_info)
            masked_path = os.path.join(MAIN_DIR, f"{txt_file}_masked.txt")
            with open(masked_path, 'w', encoding='utf-8') as f:
                f.write(masked_text)
            print(f"[⚠️] 마스킹된 결과 저장 완료: {masked_path}")

            connectDatabase.updatePersonalInfoTrue(txt_file)
        else:
            print(f"[✅] 개인정보 미발견: {txt_file}")

    print("=" * 80)

    # 하위 폴더별 OCR + 이미지 마스킹 처리
    for folder in os.listdir(MAIN_DIR):
        folder_path = os.path.join(MAIN_DIR, folder)
        if not os.path.isdir(folder_path):
            continue

        print(f"[📂] 하위 폴더 처리: {folder_path}")
        image_files = sorted([f for f in os.listdir(folder_path) if f.endswith('.png')])

        all_texts = []
        all_json = []

        for img_file in image_files:
            img_path = os.path.join(folder_path, img_file)
            full_text, ocr_json = call_clova_ocr(img_path)
            all_texts.append(full_text)
            all_json.append((img_path, ocr_json))

        if not all_texts:
            print(f"[ℹ️] 이미지 없음, 스킵: {folder_path}")
            continue

        full_text = "\n".join(all_texts)

        result_path = os.path.join(folder_path, "ocr_result.txt")
        with open(result_path, 'w', encoding='utf-8') as f:
            f.write(full_text)
        print(f"[📝] OCR 결과 저장 완료: {result_path}")

        pii_data = detectUseLLM.detect_pii_with_ollama(full_text)

        found_info = []
        for values in pii_data.values():
            found_info.extend(values)

        if found_info:
            info_path = os.path.join(folder_path, "detected_personal_info.txt")
            with open(info_path, 'w', encoding='utf-8') as f:
                for item in found_info:
                    f.write(item + "\n")
            print(f"[🔐] 이미지 내 개인정보 {len(found_info)}건 저장 완료: {info_path}")

            connectDatabase.updatePersonalInfoTrue(folder)

            for img_path, ocr_json in all_json:
                infoBlur.blur_sensitive_info_from_pii(img_path, ocr_json, pii_data)

            masked_text = mask_personal_info(full_text, found_info)
            masked_path = os.path.join(folder_path, "masked_result.txt")
            with open(masked_path, 'w', encoding='utf-8') as f:
                f.write(masked_text)
            print(f"[⚠️] 이미지 OCR 마스킹 결과 저장 완료: {masked_path}")
        else:
            print("[✅] 이미지 내 개인정보 미발견")

        print("=" * 80)



def main(mainroot):
    detectUseLLM.startOllama()
    convertDoc.convert_documents(mainroot)
    ocr_documents(mainroot)


# ===== 실행 =====
if __name__ == "__main__":
    mainroot = '/Users/leejaeyoon/opt/isolation'
    #mainroot = 'D:\\Code\\isolation' 

    #scan_documents_for_personal_info(input_directory)
    detectUseLLM.startOllama()
    convertDoc.convert_documents(mainroot)
    ocr_documents(mainroot)

