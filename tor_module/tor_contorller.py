from stem import Signal #stem:Tor 제어 라이브러리
from stem.control import Controller

def renew_tor_ip(control_port=9051, password='your_password'):
    #tor --hash-password your_password - 해시된 비밀번호 확인
    with Controller.from_port(port=control_port) as controller:
        controller.authenticate(password=password)
        controller.signal(Signal.NEWNYM) #IP 변경 명령어
#torrc 파일에 ControlPort 9051과 HashedControlPassword가 있어야함


def check_ip():
    import requests
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050',
    }
    r = requests.get("http://httpbin.org/ip", proxies=proxies)
    return r.text
#Tor SOCKS5 프록시를 통해 현재 외부에서 보이는 IP 확인
#httpbin.org/ip 에서 응답받은 IP는 실제 Tor 네트워크를 통해 보이는 IP
