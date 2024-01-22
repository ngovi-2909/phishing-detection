import ipaddress
import re
import socket
from urllib.parse import urlparse
import urllib
from datetime import datetime
import time
import requests
from ipaddress import ip_address, IPv4Address, IPv6Address



def get_hostname(url):
    parsed_url = urlparse(url)
    return parsed_url.hostname


# 1
def is_ip(url):
    try:
        if (type(ip_address(url)) is IPv4Address) or (type(ip_address(url)) is IPv6Address):
            return 1
        else:
            ip = get_hostname(url)
            return 1 if type(ip_address(ip)) is IPv4Address or IPv6Address else 0
    except:
        return 0


# 2
def length_url(url):
    return len(url)


# 3
def length_hostname(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return len(hostname)


# 4
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


def tiny_url(url):
    match = re.search(shortening_services, url)
    if match:
        return 1
    else:
        return 0


# 5
def countAtSign(url):
    return len(re.findall("\@", url))


# 6
def countQuestionMark(url):
    len(re.findall("\?", url))


# 7
def countHyphen(url):
    len(re.findall("\-", url))


# 8
def countDot(url):
    return len(re.findall("\.", url))


# 9
def countComma(url):
    return len(re.findall("\,", url))


# 10
def countSemicolon(url):
    return len(re.findall("\;", url))


# 11
def countDollar(url):
    return len(re.findall("\$", url))


# 12
def countAnd(url):
    return len(re.findall("\&"), url)


# 13
def countSlash(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    return len(re.findall("\/"), url)


# redirect '//' 14
def have_redirect(url):
    parsed_url = urllib.parse.urlparse(url)
    protocol = parsed_url.scheme
    position = url.rfind('//')

    if (protocol == 'http' and position > 6) or (protocol == 'https' and position > 7):
        return 1
    else:
        return 0


# 15
def CountEqual(url):
    return len(re.findall("\=", url))


# 16
def CountPercent(url):
    return len(re.findall("\%", url))


# 17
def CountUnderScore(url):
    return len(re.findall("\_", url))


# 18
def CountDotHostName(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return len(re.findall("\.", hostname))


# 19
def CountColon(url):
    return len(re.findall("\:", url))


# 20
def CountStar(url):
    return len(re.findall("\*", url))


# 21
def CountHttp(url):
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme
    print(re.findall("http", url))
    if (protocol == "http" or protocol == "https"):
        return len(re.findall("http", url)) - 1
    return len(re.findall("http", url))


# 22
def check_https_protocol(url):
    parsed_url = urlparse(url)
    protocol = parsed_url.scheme
    if protocol == 'https':
        return 1
    return 0


# 23
def RatioDigitsInHostname(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    return len(re.sub("[^0-9]", "", hostname)) / len(hostname)


# 24
def RatioDigitsURL(url):
    return len(re.sub("[^0-9]", "", url)) / len(url)


# 25
def have_prefixOrSuffix(url):
    domain = urlparse(url).netloc
    if '-' in domain:
        return 1
    else:
        return 0


# 26
def web_forwarding(response):
    return len(response.history)


# 27
# DomainRegLen
def DomainRegLen(whois_response):
    try:
        expiration_date = whois_response.expiration_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return 0


# 28
def DomainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if creation_date:
            if type(creation_date) == list:
                creation_date = min(creation_date)
            return abs((creation_date - today).days)
        else:
            return 0
    except:
        return 0


# 29
def page_rank(key, url):
    domain = urlparse(url).netloc
    page = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    try:
        request = requests.get(page, headers={'API-OPR': key})
        result = request.json()
        result = result['response'][0]['page_rank_integer']
        if result:
            return result
        else:
            return 0
    except:
        pass


# #30
def dns_expiration_length(url):
    try:
        return 0 if len(socket.gethostbyname(get_hostname(url))) > 0 else 1
    except:
        return 1