import requests

def tor_get(url, headers=None, params=None):
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050',
    }
    response = requests.get(url, headers=headers, params=params, proxies=proxies, timeout=10)
    return response
#socks5h는 DNS 요청도 Tor 경유하게 만듦