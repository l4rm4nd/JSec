# JSec
JavaScript and HTML Security Analysis using Semgrep and Trufflehog

## Installation

````
git clone https://github.com/l4rm4nd/JSec && cd JSec
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
npm install -g js-beautify
````

## Usage

````
usage: jsec.py [-h] --url URL [--output OUTPUT] [--depth DEPTH] [--skip-semgrep] [--skip-trufflehog]

JavaScript Security Analyzer - Crawl, extract, and analyze JavaScript files

options:
  -h, --help            show this help message and exit
  --url URL             URL of the website to analyze
  --output, -o OUTPUT   Output directory (default: js_analysis_TIMESTAMP)
  --depth, -d DEPTH     Spider depth (default: 1)
  --skip-semgrep, -s    Skip Semgrep analysis
  --skip-trufflehog, -t
                        Skip TruffleHog analysis

Examples:
  jsec.py --url https://example.com
  jsec.py --url https://example.com --depth 2 --output my_analysis
  jsec.py --url https://example.com --skip-semgrep

Requirements:
  - Chrome/Chromium browser
  - chromedriver
  - js-beautify (npm install -g js-beautify)
  - docker (for Semgrep and TruffleHog)
  - Python packages: selenium, beautifulsoup4, requests, tldextract

````
