import requests
import re
import json
import subprocess
import platform
import requests
import time

def detect_pii_with_ollama(text, model='llama3.2-bllossom-kor-3B'):
    prompt = f"""
다음 텍스트에서 이름, 전화번호, 주민등록번호, 이메일, 주소 등 **개인정보**로 판단되는 항목들을 찾아주세요.

조건:
- 단순히 "있다/없다"가 아니라, 실제 발견된 개인정보 문자열을 항목별로 정확히 리스트로 분류해 주세요.
- 추가 설명은 하지 말고, 결과만 **JSON 형식**으로 출력해 주세요.
- 출력은 반드시 아래 형식과 같은 JSON만 포함되어야 하며, 순서와 키 이름도 동일하게 유지해 주세요.

형식 예시:
{{
  "이름": ["홍길동", "김민수"],
  "전화번호": ["010-1234-5678"],
  "이메일": ["test@example.com"],
  "주소": ["서울시 강남구 테헤란로 123"],
  "기타": ["900101-1234567"]
}}

이제 아래 텍스트를 분석해 주세요:
{text[:2000]}
"""


    try:
        response = requests.post(
            'http://localhost:11434/api/generate',
            json={'model': model, 'prompt': prompt, 'stream': False}
        )
        result = response.json()
        raw_output = result.get('response', '')

        # JSON 부분만 추출
        json_match = re.search(r'\{.*\}', raw_output, re.DOTALL)
        if not json_match:
            raise ValueError("JSON 형식 응답을 찾을 수 없음")

        json_str = json_match.group(0)
        pii_data = json.loads(json_str)
        return pii_data
    except Exception as e:
        print("[⚠️] LLM 응답 파싱 실패:", e)
        return {}


def ollamaRunningCheck():
    try:
        res = requests.get("http://localhost:11434")
        return res.status_code == 200
    except Exception:
        return False

def startOllama():
    system = platform.system()
    print(f"[🧠] Ollama 서버 확인 중...")

    if ollamaRunningCheck():
        print("[✅] Ollama가 이미 실행 중입니다.")
        return

    try:
        if system == 'Windows':
            # 윈도우는 start 명령어를 이용해 별도 콘솔에서 백그라운드 실행
            subprocess.Popen("start ollama serve", shell=True)
        elif system == 'Darwin':  # macOS
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif system == 'Linux':  # Ubuntu 포함
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            raise RuntimeError("지원되지 않는 운영체제입니다.")
        print("[🚀] Ollama 서버 시작 중... 잠시 기다립니다.")
        time.sleep(3)
    except Exception as e:
        print(f"[❌] Ollama 실행 실패: {e}")