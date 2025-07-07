# Created by Nemesis
# nemesisuks@protonmail.com

import requests
import cloudscraper
from bs4 import BeautifulSoup
import re
from typing import Optional, Dict
from urllib.parse import urljoin, urlparse
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import argparse
import json
import time
import random
import os

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException, WebDriverException

DEFAULT_LOG_FILE        = "vuln_scan.log"
POC_FILE                = "PoC.txt"
DEFAULT_OUTPUT_DIR      = "results"
USER_AGENTS_FILE        = "user_agents.txt"

VULN_PATTERNS = {
    r'URLSearchParams\.get\(': 'xss',
    r'eval\(':               'xss',
    r'\.innerHTML\s*=':      'xss',
    r'document\.write\(':    'xss',
    r'location\s*\.':        'xss',
    r'new\s+Function\(':     'xss',
}
COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), tag) for p, tag in VULN_PATTERNS.items()]

def load_user_agents(path: str = USER_AGENTS_FILE) -> list:
    try:
        with open(path, "r", encoding="utf-8") as f:
            agents = [line.strip() for line in f if line.strip()]
            if not agents:
                print(f"Warning: User-agent file '{path}' is empty.")
            return agents
    except FileNotFoundError:
        print(f"Warning: User-agent file '{path}' not found.")
        return []

USER_AGENTS = load_user_agents()

def get_random_user_agent() -> str:
    agent = random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0"
    print(f"[DEBUG] Using User-Agent: {agent}")
    return agent

def load_payloads(path: str = "payloads.txt") -> list:
    try:
        with open(path, "r", encoding="utf-8") as f:
            payloads = [line.strip() for line in f if line.strip()]
            if not payloads:
                print(f"Warning: Payload file '{path}' is empty.")
            else:
                print(f"Loaded {len(payloads)} payloads from '{path}'.")
            return payloads
    except FileNotFoundError:
        print(f"Warning: Payload file '{path}' not found.")
        return []

XSS_PAYLOADS = load_payloads()

def setup_logger(path: str) -> logging.Logger:
    log = logging.getLogger("VulnScanner")
    if not log.hasHandlers():
        log.setLevel(logging.DEBUG)
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)
        log.addHandler(ch)
        fh = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    return log

def create_requests_session(cookie: Optional[str] = None) -> requests.Session:
    session = cloudscraper.create_scraper()
    user_agent = get_random_user_agent()
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml",
    })
    if cookie:
        session.headers['Cookie'] = cookie
    return session

def is_cloudflare_challenge(html: str, status_code: int, headers: Dict[str, str]) -> bool:
    patterns = [
        "cf-browser-verification", "Checking your browser before accessing",
        "Cloudflare Ray ID", "Please enable JavaScript", "id=\"challenge-form\""
    ]
    if status_code in {403, 429, 503}:
        return True
    return any(p in html for p in patterns)

def create_browser(url: str, cookie: Optional[str] = None, headless: bool = True) -> webdriver.Chrome:
    opts = Options()
    if headless:
        opts.add_argument('--headless')
    opts.add_argument('--disable-gpu')
    opts.add_argument('--no-sandbox')
    opts.add_argument('--log-level=3')
    ua = get_random_user_agent()
    opts.add_argument(f'user-agent={ua}')
    driver = webdriver.Chrome(options=opts)
    driver.get(url)
    if cookie:
        domain = urlparse(url).hostname
        for pair in cookie.split(';'):
            if '=' in pair:
                k, v = pair.strip().split('=', 1)
                try:
                    driver.add_cookie({'name': k, 'value': v, 'domain': domain, 'path': '/'})
                except WebDriverException:
                    pass
        driver.get(url)
    return driver

def fetch_js_from_url(url: str, session: requests.Session, logger: logging.Logger) -> list:
    js_sources = []
    try:
        browser = create_browser(url)
        WebDriverWait(browser, 15).until(lambda d: d.execute_script("return document.readyState") == "complete")
        soup = BeautifulSoup(browser.page_source, 'html.parser')

        for i, tag in enumerate(soup.find_all('script', src=None), 1):
            code = tag.get_text().strip()
            if code:
                js_sources.append((f"inline#{i}", code))

        for tag in soup.find_all('script', src=True):
            src = urljoin(url, tag['src'])
            try:
                r2 = session.get(src, timeout=10)
                r2.raise_for_status()
                js_sources.append((src, r2.text))
            except Exception as e:
                logger.warning(f"Failed fetching JS {src}: {e}")
    finally:
        try: browser.quit()
        except: pass
    return js_sources

def search_vulns(js_sources: list, logger: logging.Logger) -> list:
    found = []
    for name, code in js_sources:
        for pat, tag in COMPILED_PATTERNS:
            for m in pat.finditer(code):
                snippet = code[max(0, m.start()-30):m.end()+30].replace('\n',' ')
                logger.info(f"[{name}] Pattern '{pat.pattern}' → {tag}\n    …{snippet}…")
                if tag == 'xss':
                    found.append({"pattern": pat.pattern, "location": name, "snippet": snippet})
    if not found:
        logger.info("No XSS patterns detected.")
    else:
        logger.info(f"Found {len(found)} XSS patterns.")
    return found

def save_poc(url: str, desc: str = "", payload: str = ""):
    with open(POC_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[{datetime.utcnow().isoformat()}] {desc} :: {url} :: Payload={payload}\n")

def perform_poc_tests(url: str, injection_points: list, session: requests.Session,
                      logger: logging.Logger, cookie: Optional[str] = None,
                      no_cookies: bool = False, keep_going: bool = False,
                      delay: int = 5):

    if not injection_points:
        logger.info("No injection points to test.")
        return

    def filter_inputs(elems):
        return [e for e in elems if (e.get_attribute("name") or "").lower() != "password" and
                (e.get_attribute("type") or "").lower() != "password"]

    def describe(e):
        return f"<{e.tag_name} type='{e.get_attribute('type') or ''}' name='{e.get_attribute('name') or ''}'>"

    def inject_js(e, payload):
        try:
            driver = e._parent
            driver.execute_script("arguments[0].value=arguments[1];", e, payload)
            driver.execute_script("""
                var ev = new Event('input',{bubbles:true});
                arguments[0].dispatchEvent(ev);
                var ev2 = new Event('change',{bubbles:true});
                arguments[0].dispatchEvent(ev2);
            """, e)
        except:
            pass

    def try_handle_alert_and_save(form_idx, payload):
        try:
            WebDriverWait(browser, 6).until(EC.alert_is_present())
            alert = browser.switch_to.alert
            logger.info(f"[+] XSS triggered! Alert text: {alert.text}")
            alert.accept()
            time.sleep(0.5)
            save_poc(browser.current_url, f"Form#{form_idx+1}", payload)
            return True
        except TimeoutException:
            return False
        except UnexpectedAlertPresentException:
            try:
                browser.switch_to.alert.accept()
                time.sleep(0.5)
                save_poc(browser.current_url, f"Form#{form_idx+1}", payload)
                return True
            except:
                return False

    logger.info(f"Running PoC tests in {'no-cookies' if no_cookies else 'normal'} mode. Keep going: {keep_going}. Delay: {delay}s")

    if no_cookies:
        for form_idx in range(1000):
            for payload in XSS_PAYLOADS[:3]:
                browser = create_browser(url, cookie=cookie, headless=False)
                WebDriverWait(browser, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
                time.sleep(delay)
                forms = browser.find_elements(By.TAG_NAME, "form")
                if form_idx >= len(forms):
                    if form_idx == 0:
                        logger.info("No forms detected.")
                    browser.quit()
                    break
                form = forms[form_idx]
                inputs = filter_inputs(form.find_elements(By.TAG_NAME, "input") + form.find_elements(By.TAG_NAME, "textarea"))
                for e in inputs:
                    logger.info(f"Injecting payload '{payload}' into element {describe(e)}")
                    inject_js(e, payload)
                time.sleep(0.5)
                try:
                    form.submit()
                except:
                    try:
                        form.find_element(By.CSS_SELECTOR, "input[type=submit],button[type=submit]").click()
                    except:
                        logger.warning(f"Cannot submit form #{form_idx+1}")
                if try_handle_alert_and_save(form_idx, payload):
                    browser.quit()
                    if not keep_going:
                        return
                browser.quit()
            else:
                continue
            break
    else:
        browser = create_browser(url, cookie=cookie, headless=False)
        WebDriverWait(browser, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
        time.sleep(delay)
        forms = browser.find_elements(By.TAG_NAME, "form")
        logger.info(f"Detected {len(forms)} forms.")
        for form_idx in range(len(forms)):
            for payload in XSS_PAYLOADS[:3]:
                browser.get(url)
                WebDriverWait(browser, 10).until(lambda d: d.execute_script("return document.readyState") == "complete")
                time.sleep(delay)
                forms = browser.find_elements(By.TAG_NAME, "form")
                if form_idx >= len(forms):
                    continue
                form = forms[form_idx]
                inputs = filter_inputs(form.find_elements(By.TAG_NAME, "input") + form.find_elements(By.TAG_NAME, "textarea"))
                for e in inputs:
                    logger.info(f"Injecting payload '{payload}' into element {describe(e)}")
                    inject_js(e, payload)
                time.sleep(0.5)
                try:
                    form.submit()
                except:
                    try:
                        form.find_element(By.CSS_SELECTOR, "input[type=submit],button[type=submit]").click()
                    except:
                        logger.warning(f"Cannot submit form #{form_idx+1}")
                if try_handle_alert_and_save(form_idx, payload):
                    if not keep_going:
                        browser.quit()
                        return
        browser.quit()

def main():
    parser = argparse.ArgumentParser("XSSniper")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-c","--cookie", help="Cookie header")
    parser.add_argument("-l","--logfile", default=DEFAULT_LOG_FILE)
    parser.add_argument(
        "--poc",
        nargs='?',
        const=True,
        default=False,
        help="Enter PoC mode (optionally supply a JSON file path)"
    )
    parser.add_argument("--no-cookies", action="store_true",
                        help="Clear cookies per payload injection")
    parser.add_argument("--keep-going", action="store_true",
                        help="Continue testing all injection points after finding XSS")
    parser.add_argument(
    "--delay",
    type=int,
    default=5,
    help="Delay in seconds after page load before testing (default: 5)"
    )
    args = parser.parse_args()

    logger = setup_logger(args.logfile)
    session = create_requests_session(args.cookie)

    try:
        r = session.get(args.url, timeout=10)
        if is_cloudflare_challenge(r.text, r.status_code, r.headers):
            logger.warning("Cloudflare/WAF detected.")
        r.raise_for_status()
    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return

    parsed_url = urlparse(args.url)
    domain = parsed_url.hostname or "unknown"
    os.makedirs(DEFAULT_OUTPUT_DIR, exist_ok=True)
    domain_file = os.path.join(DEFAULT_OUTPUT_DIR, f"{domain}.json")

    if not args.poc:
        js_src = fetch_js_from_url(args.url, session, logger)
        points = search_vulns(js_src, logger)
        with open(domain_file, "w", encoding="utf-8") as f:
            json.dump({
                "url": args.url,
                "scanned_at": datetime.utcnow().isoformat(),
                "injection_points": points
            }, f, indent=2)
        logger.info(f"Saved injection points to {domain_file}")
        logger.info("Re-run with --poc to inject PoCs.")
    else:
        file_to_load = domain_file if args.poc is True else args.poc
        try:
            with open(file_to_load, "r", encoding="utf-8") as f:
                data = json.load(f)
                points = data.get("injection_points", [])
        except Exception as e:
            logger.error(f"Failed loading {file_to_load}: {e}")
            return
        logger.info(f"Loaded {len(points)} injection points.")
        perform_poc_tests(
            args.url, points, session, logger,
            cookie=args.cookie,
            no_cookies=args.no_cookies,
            keep_going=args.keep_going,
            delay=args.delay
        )

if __name__ == "__main__":
    main()
