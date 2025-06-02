import yara
import os

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
            return [match.rule for match in matches]
        except Exception as e:
            print(f"[!] 오류 - {file_path}: {e}")
            return []
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

# 메인 실행 예시
if __name__ == "__main__":
    target_dir = "/opt/isolation"
    detections = scan_directory(target_dir)

    print("==== YARA 탐지 결과 ====")
    for path, rules in detections.items():
        print(f"[+] {path} → {rules}")