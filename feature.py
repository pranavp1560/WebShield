import re
import socket
import requests
import urllib
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = self.get_domain()
        self.features = []
        self.status = True
        self.extract_features()

    def get_domain(self):
        try:
            domain = urlparse(self.url).netloc
            return domain.replace("www.", "")
        except:
            return ''

    def is_domain_resolvable(self):
        try:
            socket.gethostbyname(self.domain)
            return True
        except:
            return False

    def extract_features(self):
        if not self.is_domain_resolvable():
            self.features = [-1] * 30
            return

        self.features.append(self.using_ip())
        self.features.append(self.long_url())
        self.features.append(self.short_url())
        self.features.append(self.symbol_at())
        self.features.append(self.redirecting())
        self.features.append(self.prefix_suffix())
        self.features.append(self.sub_domains())
        self.features.append(self.ssl_final_state())
        self.features.append(self.domain_registration_length())
        self.features.append(self.favicon())
        self.features.append(self.port())
        self.features.append(self.https_token())
        self.features.append(self.request_url())
        self.features.append(self.url_of_anchor())
        self.features.append(self.links_in_tags())
        self.features.append(self.sfh())
        self.features.append(self.submit_to_email())
        self.features.append(self.abnormal_url())
        self.features.append(self.redirect())
        self.features.append(self.on_mouseover())
        self.features.append(self.right_click())
        self.features.append(self.popup_window())
        self.features.append(self.iframe())
        self.features.append(self.age_of_domain())
        self.features.append(self.dns_record())
        self.features.append(self.web_traffic())
        self.features.append(self.page_rank())
        self.features.append(self.google_index())
        self.features.append(self.links_pointing_to_page())
        self.features.append(self.stats_report())

    def getFeaturesList(self):
        return self.features

    # === Feature Definitions ===

    def using_ip(self):
        try:
            return -1 if re.match(r"\d+\.\d+\.\d+\.\d+", self.url) else 1
        except:
            return -1

    def long_url(self):
        return -1 if len(self.url) >= 75 else 1

    def short_url(self):
        shortening_services = r"bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co"
        return -1 if re.search(shortening_services, self.url) else 1

    def symbol_at(self):
        return -1 if '@' in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefix_suffix(self):
        return -1 if '-' in self.domain else 1

    def sub_domains(self):
        dots = self.domain.split('.')
        return -1 if len(dots) > 3 else 1

    def ssl_final_state(self):
        return 1 if self.url.startswith("https") else -1

    def domain_registration_length(self):
        try:
            w = whois.whois(self.domain)
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            length = (expiration_date - datetime.now()).days
            return 1 if length >= 365 else -1
        except:
            return -1

    def favicon(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
            if icon_link and self.domain not in icon_link['href']:
                return -1
            return 1
        except:
            return -1

    def port(self):
        return 1

    def https_token(self):
        return -1 if 'https' in self.domain else 1

    def request_url(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            imgs = soup.find_all('img', src=True)
            total = len(imgs)
            external = sum(1 for img in imgs if self.domain not in img['src'])
            return 1 if total == 0 else (-1 if (external / total) > 0.5 else 1)
        except:
            return -1

    def url_of_anchor(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            anchors = soup.find_all('a', href=True)
            total = len(anchors)
            unsafe = sum(1 for a in anchors if '#' in a['href'] or 'javascript' in a['href'].lower() or self.domain not in a['href'])
            return 1 if total == 0 else (-1 if (unsafe / total) > 0.67 else 1)
        except:
            return -1

    def links_in_tags(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            metas = soup.find_all('meta')
            links = soup.find_all('link')
            scripts = soup.find_all('script')
            total = len(metas) + len(links) + len(scripts)
            external = sum(1 for tag in metas + links + scripts if self.domain not in str(tag))
            return 1 if total == 0 else (-1 if (external / total) > 0.5 else 1)
        except:
            return -1

    def sfh(self):
        try:
            response = requests.get(self.url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form', action=True)
            for form in forms:
                if form['action'] == "" or "about:blank" in form['action'] or self.domain not in form['action']:
                    return -1
            return 1
        except:
            return -1

    def submit_to_email(self):
        try:
            response = requests.get(self.url)
            return -1 if "mailto:" in response.text else 1
        except:
            return -1

    def abnormal_url(self):
        try:
            w = whois.whois(self.domain)
            return 1 if w.domain_name else -1
        except:
            return -1

    def redirect(self):
        try:
            r = requests.get(self.url)
            return -1 if len(r.history) > 1 else 1
        except:
            return -1

    def on_mouseover(self):
        try:
            response = requests.get(self.url)
            return -1 if "onmouseover" in response.text else 1
        except:
            return -1

    def right_click(self):
        try:
            response = requests.get(self.url)
            return -1 if "event.button==2" in response.text else 1
        except:
            return -1

    def popup_window(self):
        try:
            response = requests.get(self.url)
            return -1 if "alert(" in response.text else 1
        except:
            return -1

    def iframe(self):
        try:
            response = requests.get(self.url)
            return -1 if "<iframe" in response.text.lower() else 1
        except:
            return -1

    def age_of_domain(self):
        try:
            w = whois.whois(self.domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (datetime.now() - creation_date).days
            return 1 if age > 180 else -1
        except:
            return -1

    def dns_record(self):
        try:
            w = whois.whois(self.domain)
            return 1 if w else -1
        except:
            return -1

    def web_traffic(self):
        return 0  # Unknown

    def page_rank(self):
        return 0  # Unknown

    def google_index(self):
        try:
            query = f"https://www.google.com/search?q=site:{self.domain}"
            response = requests.get(query, headers={"User-Agent": "Mozilla/5.0"})
            return 1 if "did not match any documents" not in response.text else -1
        except:
            return -1

    def links_pointing_to_page(self):
        return 0

    def stats_report(self):
        return 0