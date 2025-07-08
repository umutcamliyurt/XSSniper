#!/usr/bin/env python3

# Created by Nemesis
# nemesisuks@protonmail.com

import argparse
import json
import logging
import os
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, urlencode, urldefrag, parse_qs

import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.common.exceptions import (
    WebDriverException,
    TimeoutException,
    NoAlertPresentException,
)
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

DEFAULT_LOG_FILE   = "vuln_scan.log"
DEFAULT_OUTPUT_DIR = "results"
POC_FILE_NAME      = "PoC.txt"
USER_AGENTS_FILE   = "user_agents.txt"
PAYLOADS_FILE      = "payloads.txt"

VULN_PATTERNS = {
    r'URLSearchParams\.get\(': 'xss',
    r'eval\(':               'xss',
    r'\.innerHTML\s*=':      'xss',
    r'document\.write\(':    'xss',
    r'location\s*\.':        'xss',
    r'new\s+Function\(':     'xss',
}
COMPILED_PATTERNS = [(re.compile(p, re.IGNORECASE), tag) for p, tag in VULN_PATTERNS.items()]


def load_lines(path: str) -> List[str]:
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def load_fuzz_params() -> List[str]:
    path = "fuzz-params.txt"
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

USER_AGENTS  = load_lines(USER_AGENTS_FILE)
XSS_PAYLOADS = load_lines(PAYLOADS_FILE) or ["<script>alert(1)</script>"]

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS) if USER_AGENTS else "Mozilla/5.0 (X11; Linux x86_64)"

def setup_logger(logfile: str, verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("XSSniper")
    if logger.handlers:
        return logger
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S")
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    os.makedirs(os.path.dirname(logfile) or '.', exist_ok=True)
    fh = RotatingFileHandler(logfile, maxBytes=5_000_000, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger

def parse_cookie_header(header: str) -> Dict[str, str]:
    return dict(pair.strip().split('=', 1) for pair in header.split(';') if '=' in pair)


def is_cloudflare_challenge(html: str, status_code: int, headers: Dict[str, str]) -> bool:
    patterns = [
        "cf-browser-verification",
        "Checking your browser before accessing",
        "Cloudflare Ray ID",
        "Please enable JavaScript",
        "id=\"challenge-form\""
    ]
    if status_code in {403, 429, 503}:
        return True
    return any(p in html for p in patterns)


def create_session(cookie_header: Optional[str], test_url: str, logger: logging.Logger):
    session = requests.Session()
    user_agent = get_random_user_agent()
    session.headers.update({
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml',
    })
    if cookie_header:
        for k, v in parse_cookie_header(cookie_header).items():
            session.cookies.set(k, v)

    def is_blocked(resp_text: str, status_code: int, headers: Dict[str, str]) -> bool:
        return is_cloudflare_challenge(resp_text, status_code, headers)

    try:
        logger.info(f"[*] Testing {test_url} via requests...")
        resp = session.get(test_url, timeout=10)
        if is_blocked(resp.text, resp.status_code, resp.headers):
            raise Exception("Blocked by Cloudflare or similar")
        return session
    except Exception as e:
        logger.warning(f"Request test failed ({e}); trying cloudscraper...")
        try:
            import cloudscraper
            scraper = cloudscraper.create_scraper()
            scraper.headers.update(session.headers)
            resp2 = scraper.get(test_url, timeout=15)
            if not is_blocked(resp2.text, resp2.status_code, resp2.headers):
                logger.info("Cloudscraper succeeded.")
                return scraper
            else:
                logger.warning("Cloudscraper also blocked; launching browser for manual captcha solution.")
        except Exception as ce:
            logger.warning(f"Cloudscraper setup failed ({ce}); launching browser for manual captcha solution.")

    logger.info("Please solve the captcha in the opened browser. Then return here and press Enter to continue.")
    driver = launch_browser(test_url, cookie_header, headless=False)
    input("Press Enter after solving captcha in the browser...")

    time.sleep(5)

    session.cookies.clear()

    selenium_cookies = driver.get_cookies()
    domain = urlparse(test_url).hostname
    for c in selenium_cookies:
        cookie_args = {
            'name': c['name'],
            'value': c['value'],
            'domain': c.get('domain', domain),
            'path': c.get('path', '/'),
        }
        if 'expiry' in c:
            cookie_args['expires'] = c['expiry']
        session.cookies.set(**cookie_args)

    try:
        ua = driver.execute_script("return navigator.userAgent;")
        session.headers.update({'User-Agent': ua})
        logger.info(f"Using User-Agent from browser: {ua}")
    except Exception:
        logger.debug("Could not retrieve user-agent from browser; using default.")

    driver.quit()

    try:
        resp = session.get(test_url, timeout=10)
        if is_blocked(resp.text, resp.status_code, resp.headers):
            raise Exception("Still blocked after captcha")
        return session
    except Exception as e:
        logger.error(f"Failed to fetch page after captcha with session: {e}")
        sys.exit(1)


def launch_browser(url: str, cookie_header: Optional[str], headless: bool) -> webdriver.Chrome:
    options = Options()
    if headless:
        options.add_argument('--headless')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    user_agent = get_random_user_agent()
    options.add_argument(f"--user-agent={user_agent}")
    options.add_argument("--disable-blink-features=AutomationControlled")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option('useAutomationExtension', False)

    try:
        driver = webdriver.Chrome(options=options)
        driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
            'source': '''
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            '''
        })
    except WebDriverException as e:
        raise RuntimeError(f"Failed to start Chrome driver: {e}")

    driver.get("about:blank")

    if cookie_header:
        domain = urlparse(url).hostname or ''
        for name, val in parse_cookie_header(cookie_header).items():
            try:
                driver.add_cookie({'name': name, 'value': val, 'domain': domain, 'path': '/'})
            except Exception:
                pass
    driver.get(url)
    return driver

def crawl_site(start_url: str, session, logger: logging.Logger, max_pages: int = 50) -> List[str]:
    visited, queue, results = set(), [start_url], []
    domain = urlparse(start_url).netloc
    while queue and len(visited) < max_pages:
        page = urldefrag(queue.pop(0)).url
        if page in visited:
            continue
        try:
            logger.info(f"Crawling: {page}")
            resp = session.get(page, timeout=10)
            resp.raise_for_status()
            visited.add(page)
            results.append(page)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for a in soup.find_all('a', href=True):
                link = urljoin(page, a['href'])
                if urlparse(link).netloc == domain and link not in visited and link not in queue:
                    queue.append(link)
        except Exception as e:
            logger.debug(f"Skipping {page}: {e}")
    return results


def fetch_js(page: str, session, logger: logging.Logger) -> List[tuple]:
    sources = []
    logger.debug(f"Fetching JS for {page}")
    driver = None
    try:
        driver = launch_browser(page, None, headless=True)
        WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
        soup = BeautifulSoup(driver.page_source, 'html.parser')

        for idx, tag in enumerate(soup.find_all('script', src=None), 1):
            code = tag.string or ''
            if code.strip():
                sources.append((f'inline#{idx}', code))

        for tag in soup.find_all('script', src=True):
            src = urljoin(page, tag['src'])
            try:
                js = session.get(src, timeout=10).text
                sources.append((src, js))
            except Exception as e:
                logger.warning(f"Failed to fetch external script {src}: {e}")
    except Exception as e:
        logger.warning(f"JS fetch failed on {page}: {e}")
    finally:
        if driver:
            driver.quit()
    return sources


def find_vulnerabilities(js_list: List[tuple], logger: logging.Logger, verbose: bool = False) -> List[Dict]:
    findings = []
    for src, code in js_list:
        for pattern, tag in COMPILED_PATTERNS:
            for m in pattern.finditer(code):
                snippet = code[max(0, m.start()-30):m.end()+30].replace('\n', ' ')
                if verbose:
                    logger.info(f"VULN [{src}] → {tag}: …{snippet}…")
                    print(f"VULNERABLE JS code snippet found in {src}:\n...{snippet}...\n")
                else:
                    logger.info(f"Potential vulnerable JS code found in {src} [{tag}]")
                findings.append({
                    'type': tag,
                    'pattern': pattern.pattern,
                    'source': src,
                    'snippet': snippet
                })
    return findings

def save_poc(url: str, form_name: str, payload: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    poc_path = os.path.join(output_dir, POC_FILE_NAME)
    with open(poc_path, 'a', encoding='utf-8') as f:
        ts = datetime.now(timezone.utc).isoformat()
        f.write(f"[{ts}] Form '{form_name}' on {url} with payload: {payload}\n")

def get_form_identifiers(driver) -> List[Tuple[str, str]]:
    ids = []
    forms = driver.find_elements(By.TAG_NAME, 'form')
    for idx, form in enumerate(forms):
        form_name   = form.get_attribute('name')
        form_id     = form.get_attribute('id')
        form_action = form.get_attribute('action')

        if form_name:
            ids.append(('name', form_name))
        elif form_id:
            ids.append(('id', form_id))
        elif form_action:
            short_action = form_action.split('?')[0].rstrip('/').split('/')[-1] or 'action'
            ids.append(('action', f"{short_action}_{idx}"))
        else:
            ids.append(('index', str(idx)))
    return ids


def perform_poc(
    url: str,
    session,
    logger: logging.Logger,
    cookie_header: Optional[str],
    headless: bool,
    selected_names: Optional[List[str]],
    keep_going: bool,
    delay: int,
    output_dir: str
):
    domain    = urlparse(url).hostname or 'site'
    json_path = os.path.join(output_dir, f"{domain}.json")
    try:
        with open(json_path, encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logger.error(f"Could not read scan results ({json_path}): {e}")
        return

    for entry in data.get('results', []):
        page = entry.get('url')
        logger.info(f"[PoC] Scanning {page}")

        parsed_url = urlparse(page)
        original_params = parse_qs(parsed_url.query)

        try:
            driver = launch_browser(page, cookie_header, headless)
            WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
            ids = get_form_identifiers(driver)
            driver.quit()
        except Exception as e:
            logger.warning(f"Error loading forms from {page}: {e}")
            ids = []

        if not ids:
            logger.info("No forms found on page; testing fuzz parameters via URL.")
            fuzz_params = load_fuzz_params()
            if not fuzz_params:
                fuzz_params = [f"x={urllib.parse.quote(p)}" for p in XSS_PAYLOADS]

            for payload in XSS_PAYLOADS:
                for key in original_params.keys() or ['x']:
                    injected_params = original_params.copy()
                    injected_params[key] = [payload]
                    new_query = urlencode(injected_params, doseq=True)
                    test_url = parsed_url._replace(query=new_query).geturl()

                    logger.info(f"[*] Fuzzing URL: {test_url}")
                    driver = None
                    try:
                        driver = launch_browser(test_url, cookie_header, headless)
                        WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
                        time.sleep(delay)
                        try:
                            alert = WebDriverWait(driver, 3).until(lambda d: d.switch_to.alert)
                            alert_text = alert.text
                            alert.accept()
                            save_poc(test_url, 'url_param', payload, output_dir)
                            logger.info(f"XSS confirmed via URL param: {test_url} (alert: {alert_text})")
                            if not keep_going:
                                driver.quit()
                                return
                            logger.info("--keep-going set, continuing with next payload.")
                        except (TimeoutException, NoAlertPresentException):
                            logger.debug(f"No alert for payload {payload} on {test_url}")
                    except Exception as e:
                        logger.debug(f"Error during URL fuzz on {test_url}: {e}")
                    finally:
                        if driver:
                            driver.quit()
            continue

        if selected_names:
            ids = [fid for fid in ids if fid[0] == 'name' and fid[1] in selected_names]
            if not ids:
                logger.info("No matching forms on this page.")
                continue

        for fid_type, fid_val in ids:
            fname = f"{fid_type}:{fid_val}"
            logger.info(f"Testing form {fname}")
            for payload in XSS_PAYLOADS:
                driver = None
                try:
                    driver = launch_browser(page, cookie_header, headless)
                    WebDriverWait(driver, 10).until(lambda d: d.execute_script('return document.readyState') == 'complete')
                    time.sleep(delay)

                    if fid_type == 'name':
                        form = driver.find_element(By.NAME, fid_val)
                    elif fid_type == 'id':
                        form = driver.find_element(By.ID, fid_val)
                    elif fid_type == 'action':
                        form = driver.find_element(By.XPATH, f"//form[contains(@action, '{fid_val.split('_')[0]}')]")
                    else:
                        idx = int(fid_val)
                        form = driver.find_elements(By.TAG_NAME, 'form')[idx]

                    inputs = form.find_elements(By.TAG_NAME, 'input') + form.find_elements(By.TAG_NAME, 'textarea')
                    for inp in inputs:
                        if inp.get_attribute('type') != 'password':
                            driver.execute_script("arguments[0].value = arguments[1];", inp, payload)

                    try:
                        submit = form.find_element(By.CSS_SELECTOR, '[type=submit]')
                        submit.click()
                    except Exception:
                        driver.execute_script("arguments[0].submit();", form)

                    time.sleep(1)
                    try:
                        alert = WebDriverWait(driver, 3).until(lambda d: d.switch_to.alert)
                        alert_text = alert.text
                        alert.accept()
                        save_poc(page, fname, payload, output_dir)
                        logger.info(f"XSS confirmed on {fname} with payload: {payload} (alert: {alert_text})")
                        if not keep_going:
                            driver.quit()
                            return
                        logger.info("--keep-going set, continuing with next payload.")
                    except (TimeoutException, NoAlertPresentException):
                        logger.debug(f"No alert for payload {payload} on form {fname}")

                except Exception as e:
                    logger.debug(f"Error on form {fname} with payload {payload}: {e}")
                finally:
                    if driver:
                        driver.quit()

def main():
    parser = argparse.ArgumentParser(description="XSSniper - A XSS scanner with WAF bypass features")
    parser.add_argument('url', help='Target URL (include http(s)://)')
    parser.add_argument('-c', '--cookie', help='Optional cookie header', default=None)
    parser.add_argument('-o', '--output-dir', help='Directory for outputs', default=DEFAULT_OUTPUT_DIR)
    parser.add_argument('--log', help='Log file path', default=DEFAULT_LOG_FILE)
    parser.add_argument('--headless', action='store_true', help='Run browser headless')
    parser.add_argument('--poc', action='store_true', help='Enable PoC mode (requires prior scan)')
    parser.add_argument('-f', '--forms', help="Comma-separated form 'name' values for PoC (default: all)", default=None)
    parser.add_argument('--keep-going', dest='keep_going', action='store_true', help='Continue tests after first PoC found')
    parser.add_argument('--delay', type=int, default=3, help='Seconds to wait after page load')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose console logging')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    logger = setup_logger(args.log, args.verbose)
    session = create_session(args.cookie, args.url, logger)

    try:
        resp = session.get(args.url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        logger.error(f"Initial fetch failed: {e}")
        sys.exit(1)

    hostname = urlparse(args.url).hostname or 'site'
    output_json = os.path.join(args.output_dir, f"{hostname}.json")

    if not args.poc:
        logger.info("Starting site crawl & JS vulnerability scan...")
        try:
            pages = crawl_site(args.url, session, logger)
            all_results = []
            for page in pages:
                js_list = fetch_js(page, session, logger)
                if not js_list:
                    continue
                vulns = find_vulnerabilities(js_list, logger, verbose=args.verbose)
                if vulns:
                    all_results.append({'url': page, 'vulns': vulns})

            with open(output_json, 'w', encoding='utf-8') as f:
                json.dump({
                    'scanned_at': datetime.now(timezone.utc).isoformat(),
                    'results':   all_results
                }, f, indent=2)
            logger.info(f"Scan complete. Results saved to {output_json}")
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            sys.exit(1)
    else:
        selected = [s.strip() for s in args.forms.split(',')] if args.forms else None
        perform_poc(
            url            = args.url,
            session        = session,
            logger         = logger,
            cookie_header  = args.cookie,
            headless       = args.headless,
            selected_names = selected,
            keep_going     = args.keep_going,
            delay          = args.delay,
            output_dir     = args.output_dir
        )


if __name__ == '__main__':
    main()
