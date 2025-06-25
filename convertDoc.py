import os
import re
import csv
import time
import subprocess
import shutil
from dotenv import load_dotenv
from pdf2image import convert_from_path

SUPPORTED_EXTENSIONS = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'hwp', 'jpeg', 'png' , 'jpg', 'txt']


#pdf 변환
def convert_to_pdf(directory: str, input_path: str) -> str:
    output_path = os.path.join(directory, os.path.splitext(os.path.basename(input_path))[0] + ".pdf")
    command = [
        #/usr/bin/soffice, #서버용
        "/opt/homebrew/bin/soffice",
        "--headless",
        "--convert-to", "pdf",
        "--outdir", directory,
        input_path
    ]
    subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if os.path.exists(output_path):
        return output_path
    else:
        raise FileNotFoundError(f"[❌] PDF 변환 실패: {input_path}")


#pdf to hwp    
def convert_hwp_to_pdf(directory: str, input_path:str) -> str:
    output_pdf_path = os.path.join(directory, os.path.splitext(os.path.basename(input_path))[0] + ".pdf")

    try:
        subprocess.run(
            ["/opt/homebrew/bin/soffice", "--headless", "--convert-to", "pdf", "--outdir", directory, input_path],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if os.path.exists(output_pdf_path):
            print(f"[🔁] HWP → PDF 변환 완료: {output_pdf_path}")
            return output_pdf_path
        else:
            raise FileNotFoundError(f"변환된 PDF를 찾을 수 없음: {output_pdf_path}")
    except Exception as e:
        print(f"[❌] HWP 변환 실패: {input_path} - {str(e)}")
        return None    
    
def convert_documents(directory: str, delete_original: bool = False):
    SKIP_TEXT_EXTENSIONS = ['txt', 'csv', 'xlsx']
    total_duration = 0
    converted_count = 0

    for root, _, files in os.walk(directory):
        for file in files:
            if file.startswith('.'):
                continue

            file_path = os.path.join(root, file)
            ext = file.split('.')[-1].lower()

            try:
                if ext not in SUPPORTED_EXTENSIONS:
                    print(f"[⛔️] 지원하지 않는 형식 건너뜀: {file_path}")
                    continue

                if ext in SKIP_TEXT_EXTENSIONS:
                    print(f"[📄] 텍스트 기반 파일 변환 생략: {file_path}")
                    continue

                print(f"[📄] 변환 시작: {file_path}")
                start_time = time.time()

                file_base_name = os.path.splitext(file)[0]
                save_dir = os.path.join(directory, file_base_name)
                os.makedirs(save_dir, exist_ok=True)

                if ext == 'png':
                    new_path = os.path.join(save_dir, file)
                    if not os.path.exists(new_path):
                        shutil.copy2(file_path, new_path)
                    print(f"[✅] PNG 복사됨: {new_path}")

                    if delete_original:
                        os.remove(file_path)
                        print(f"[🗑] 원본 PNG 삭제됨: {file_path}")

                    end_time = time.time()
                    duration = end_time - start_time
                    total_duration += duration
                    print(f"⏱️ 변환 시간: {duration:.2f}초")
                    continue

                if ext == 'hwp':
                    pdf_path = convert_hwp_to_pdf(directory, file_path)
                    if not pdf_path:
                        continue
                else:
                    pdf_path = file_path if ext == 'pdf' else convert_to_pdf(directory, file_path)

                # PDF → 이미지 변환
                images = convert_from_path(pdf_path, dpi=300)
                for i, page in enumerate(images):
                    image_filename = f"{file_base_name}_page_{i + 1}.png"
                    image_path = os.path.join(save_dir, image_filename)
                    page.save(image_path, "PNG")

                print(f"[✅] 변환 완료: {len(images)}페이지 → {save_dir}")
                converted_count += 1

                if delete_original:
                    if ext != 'pdf':
                        os.remove(file_path)
                        print(f"[🗑] 원본 문서 삭제됨: {file_path}")
                    elif pdf_path == file_path:
                        os.remove(file_path)
                        print(f"[🗑] 원본 PDF 삭제됨: {file_path}")

                end_time = time.time()
                duration = end_time - start_time
                total_duration += duration
                print(f"⏱️ 변환 시간: {duration:.2f}초")

            except Exception as e:
                print(f"[❌] 변환 실패: {file_path} - {str(e)}")

    if converted_count > 0:
        avg_time = total_duration / converted_count
    else:
        avg_time = 0

    print("\n📊 [문서 변환 통계]")
    print(f"📄 변환된 파일 수: {converted_count}")
    print(f"⏱️ 총 소요 시간: {total_duration:.2f}초")
    print(f"📈 평균 변환 시간: {avg_time:.2f}초")




    
                
