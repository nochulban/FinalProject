from stem import Signal #stem:Tor 제어 라이브러리
from stem.control import Controller
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
import requests
#pip install stem requests

def renewTorIP(password):
    #tor --hash-password your_password - 해시된 비밀번호 확인
    control_port=9051 
    with Controller.from_port(port=control_port) as controller:
        controller.authenticate(password=password)
        controller.signal(Signal.NEWNYM) #IP 변경 명령어
#torrc 파일에 ControlPort 9051과 HashedControlPassword가 있어야함


def getCurrentIP():
    
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050',
    }
    r = requests.get("http://httpbin.org/ip", proxies=proxies)
    print(r.text)
    return r.text
#Tor SOCKS5 프록시를 통해 현재 외부에서 보이는 IP 확인
#httpbin.org/ip 에서 응답받은 IP는 실제 Tor 네트워크를 통해 보이는 IP


def create_tor_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--proxy-server=socks5://127.0.0.1:9050")  # Tor 프록시
    options.add_experimental_option("excludeSwitches", ["enable-logging"])
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

# if __name__ == '__main__':
#     renew_tor_ip()
#     check_ip()
