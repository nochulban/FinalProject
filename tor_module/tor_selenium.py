from selenium import webdriver
from selenium.webdriver.firefox.options import Options

def get_tor_driver(headless=True):
    options = Options()
    options.headless = headless
    profile = webdriver.FirefoxProfile()
    profile.set_preference("network.proxy.type", 1)
    profile.set_preference("network.proxy.socks", "127.0.0.1")
    profile.set_preference("network.proxy.socks_port", 9050)
    profile.set_preference("network.proxy.socks_remote_dns", True)

    driver = webdriver.Firefox(firefox_profile=profile, options=options)
    return driver
#FirefoxProfile을 커스터마이징하여 모든 요청을 Tor로 우회
#headless=True로 설정하면 백그랑운드 브랑우저 실행됨
#DNS도 Tor를 거치도록 설정