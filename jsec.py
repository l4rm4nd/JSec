#!/usr/bin/env python3
"""
JavaScript Security Analyzer
Author: Based on LRVT's web crawler
Description: Crawl websites, extract JavaScript files, beautify them, and run security analysis
Version: 2.1
"""

import argparse
import os
import sys
import json
import subprocess
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from pathlib import Path
import requests
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import tldextract  # kept for future use / compatibility
from pathlib import Path

class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color

def print_banner():
    print(f"{Colors.BLUE}")
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║          JavaScript Security Analyzer v2.1                     ║")
    print("╚════════════════════════════════════════════════════════════════╝")
    print(f"{Colors.NC}\n")


def print_info(msg):
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {msg}")


def print_success(msg):
    print(f"{Colors.GREEN}[SUCCESS]{Colors.NC} {msg}")


def print_warning(msg):
    print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {msg}")


def print_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def print_section(msg):
    print(f"\n{Colors.GREEN}{'═' * 63}{Colors.NC}")
    print(f"{Colors.GREEN}  {msg}{Colors.NC}")
    print(f"{Colors.GREEN}{'═' * 63}{Colors.NC}\n")

class JSSecurityAnalyzer:

    def _slugify(self, text: str, max_len: int = 80) -> str:
        text = (text or "").lower()
        text = re.sub(r"[^a-z0-9]+", "_", text)
        text = re.sub(r"_+", "_", text).strip("_")
        return text[:max_len] if len(text) > max_len else text

    def __init__(self, url, output_dir, depth=1, skip_semgrep=False, skip_trufflehog=False):
        self.inline_counter = 0
        self.base_url = url
        self.output_dir = Path(output_dir)
        self.depth = depth
        self.skip_semgrep = skip_semgrep
        self.skip_trufflehog = skip_trufflehog

        self.js_urls = set()
        self.visited_urls = set()
        self.driver = None

        # Create output directory structure
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "original_js").mkdir(exist_ok=True)
        (self.output_dir / "beautified_js").mkdir(exist_ok=True)

        # NEW: HTML output structure
        (self.output_dir / "original_html").mkdir(exist_ok=True)
        (self.output_dir / "beautified_html").mkdir(exist_ok=True)

    def setup_driver(self):
        """Setup headless Chrome browser"""
        print_info("Setting up headless Chrome browser...")
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--window-size=1920,1080')
        chrome_options.add_argument("--disable-setuid-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-blink-features=AutomationControlled")
        chrome_options.add_argument(
            "user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )

        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            print_success("Chrome browser initialized")
        except Exception as e:
            print_error(f"Failed to initialize Chrome: {e}")
            sys.exit(1)

    def extract_js_from_page(self, url):
        """Extract JavaScript URLs from a single page"""
        try:
            print_info(f"Extracting JS from: {url}")
            self.driver.get(url)

            # Wait a bit for dynamic content to load
            self.driver.implicitly_wait(3)

            page_source = self.driver.page_source
            soup = BeautifulSoup(page_source, 'html.parser')

            # Find all script tags
            js_found = 0
            for script in soup.find_all('script'):
                # External scripts
                if script.get('src'):
                    js_url = urljoin(url, script['src'])
                    if js_url not in self.js_urls:
                        self.js_urls.add(js_url)
                        js_found += 1

                # Inline scripts (save them too)
                elif script.string and len(script.string.strip()) > 50:
                    # reset per page for readability
                    if not hasattr(self, "_inline_page_url") or self._inline_page_url != url:
                        self._inline_page_url = url
                        self.inline_counter = 0

                    self.inline_counter += 1

                    u = urlparse(url)
                    page_id = self._slugify(f"{u.netloc}{u.path}") or self._slugify(u.netloc) or "page"

                    inline_name = f"inline__{page_id}__{self.inline_counter:03d}.js"
                    inline_path = self.output_dir / "original_js" / inline_name

                    with open(inline_path, "w", encoding="utf-8", errors="replace") as f:
                        f.write(script.string)

                    print_info(f"Saved inline script: {inline_name}")

            # Also check for JS files in other attributes and response
            js_patterns = [
                r'https?://[^\s"\'\)<>]+\.js(?:\?[^\s"\'<>]*)?',
                r'["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'
            ]

            for pattern in js_patterns:
                matches = re.findall(pattern, page_source)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0] if match[0] else match[1] if len(match) > 1 else ""
                    if match and not match.startswith(('http://', 'https://')):
                        match = urljoin(url, match)
                    if match and match.endswith('.js') and match not in self.js_urls:
                        self.js_urls.add(match)
                        js_found += 1

            print_success(f"Found {js_found} JS references on this page")
            return True

        except Exception as e:
            print_warning(f"Failed to extract JS from {url}: {e}")
            return False

    def spider_pages(self, url, current_depth):
        """Recursively spider pages to find more JS files"""
        if current_depth <= 0 or url in self.visited_urls:
            return

        print_info(f"Spidering (depth {current_depth}): {url}")
        self.visited_urls.add(url)

        try:
            self.driver.get(url)
            self.driver.implicitly_wait(2)
            page_source = self.driver.page_source

            # Extract JS from current page
            self.extract_js_from_page(url)

            # Find links to spider
            soup = BeautifulSoup(page_source, 'html.parser')
            base_domain = urlparse(self.base_url).netloc

            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(url, link['href'])
                parsed = urlparse(absolute_url)

                # Only follow links on same domain
                if parsed.netloc == base_domain and absolute_url not in self.visited_urls:
                    # Skip anchors, mailto, tel, etc.
                    if parsed.scheme in ['http', 'https']:
                        self.spider_pages(absolute_url, current_depth - 1)

        except Exception as e:
            print_warning(f"Failed to spider {url}: {e}")

    # -------------------------
    # NEW: Root HTML download
    # -------------------------
    def download_root_html(self):
        """Download and save the root HTML (base_url). Prefer requests, fallback to selenium."""
        print_section("Downloading Root HTML")

        original_html_dir = self.output_dir / "original_html"
        parsed = urlparse(self.base_url)
        safe_host = re.sub(r"[^\w\.-]", "_", parsed.netloc or "site")
        root_file = original_html_dir / f"root_{safe_host}.html"

        html = None

        # Try requests first
        try:
            print_info(f"Downloading HTML via requests: {self.base_url}")
            r = requests.get(
                self.base_url,
                timeout=15,
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            )
            if r.status_code == 200 and r.text and r.text.strip():
                html = r.text
            else:
                print_warning(f"requests returned status {r.status_code}, falling back to selenium")
        except Exception as e:
            print_warning(f"requests failed, falling back to selenium: {e}")

        # Fallback to selenium (dynamic DOM)
        if html is None:
            try:
                if not self.driver:
                    self.setup_driver()
                print_info(f"Downloading HTML via selenium: {self.base_url}")
                self.driver.get(self.base_url)
                self.driver.implicitly_wait(3)
                html = self.driver.page_source
            except Exception as e:
                print_error(f"Failed to capture root HTML via selenium: {e}")
                return

        try:
            with open(root_file, "w", encoding="utf-8", errors="replace") as f:
                f.write(html)
            print_success(f"Saved root HTML to: {root_file}")
        except Exception as e:
            print_error(f"Failed writing root HTML to disk: {e}")

    # -------------------------
    # NEW: HTML beautification
    # -------------------------
    def beautify_html_files(self):
        """Beautify saved HTML files."""
        print_section("Beautifying HTML Files")

        original_dir = self.output_dir / "original_html"
        beautified_dir = self.output_dir / "beautified_html"

        html_files = list(original_dir.glob("*.html"))
        if not html_files:
            print_warning("No HTML files to beautify")
            return

        # Prefer html-beautify if present, otherwise use js-beautify --type html
        def pick_beautifier_cmd():
            try:
                subprocess.run(["html-beautify", "--version"], capture_output=True, text=True, timeout=5)
                return ["html-beautify"]
            except Exception:
                return ["js-beautify", "--type", "html"]

        beautifier = pick_beautifier_cmd()

        beautified = 0
        for html_file in html_files:
            try:
                output_file = beautified_dir / html_file.name
                print_info(f"Beautifying HTML: {html_file.name}")

                result = subprocess.run(
                    beautifier + [str(html_file)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0 and result.stdout:
                    with open(output_file, "w", encoding="utf-8", errors="replace") as f:
                        f.write(result.stdout)
                    beautified += 1
                else:
                    print_warning(f"Failed to beautify {html_file.name}, copying original")
                    subprocess.run(["cp", str(html_file), str(output_file)])
            except Exception as e:
                print_warning(f"Error beautifying {html_file.name}: {e}")

        print_success(f"Beautified {beautified} HTML files")

    def download_js_files(self):
        """Download all discovered JavaScript files"""
        print_section("Downloading JavaScript Files")

        if not self.js_urls:
            print_warning("No JavaScript URLs found to download")
            return

        downloaded = 0
        for idx, js_url in enumerate(self.js_urls, 1):
            try:
                parsed = urlparse(js_url)
                filename = os.path.basename(parsed.path)

                filename = re.sub(r'[^\w\.-]', '_', filename)

                # Handle JSF/xhtml files that are actually JavaScript
                if '.js' in filename:
                    match = re.search(r'([^/]+\.js)', filename)
                    if match:
                        filename = match.group(1)

                if not filename.endswith('.js'):
                    filename = f"{filename}.js"

                if not filename or filename == '.js':
                    filename = f"script_{idx}.js"

                output_path = self.output_dir / "original_js" / filename
                counter = 1
                while output_path.exists():
                    name, ext = os.path.splitext(filename)
                    filename = f"{name}_{counter}{ext}"
                    output_path = self.output_dir / "original_js" / filename
                    counter += 1

                print_info(f"[{idx}/{len(self.js_urls)}] Downloading: {js_url}")

                response = requests.get(js_url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
                })

                if response.status_code == 200:
                    with open(output_path, 'wb') as f:
                        f.write(response.content)
                    downloaded += 1
                else:
                    print_warning(f"Failed to download (status {response.status_code}): {js_url}")

            except Exception as e:
                print_warning(f"Error downloading {js_url}: {e}")

        print_success(f"Downloaded {downloaded}/{len(self.js_urls)} JavaScript files")

    def beautify_js_files(self):
        """Beautify all downloaded JavaScript files"""
        print_section("Beautifying JavaScript Files")

        original_dir = self.output_dir / "original_js"
        beautified_dir = self.output_dir / "beautified_js"

        js_files = list(original_dir.glob("*.js"))
        if not js_files:
            print_warning("No JavaScript files to beautify")
            return

        beautified = 0
        for js_file in js_files:
            try:
                output_file = beautified_dir / js_file.name
                print_info(f"Beautifying: {js_file.name}")

                result = subprocess.run(
                    ['js-beautify', str(js_file)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    with open(output_file, 'w', encoding='utf-8', errors='replace') as f:
                        f.write(result.stdout)
                    beautified += 1
                else:
                    print_warning(f"Failed to beautify {js_file.name}, copying original")
                    subprocess.run(['cp', str(js_file), str(output_file)])

            except Exception as e:
                print_warning(f"Error beautifying {js_file.name}: {e}")

        print_success(f"Beautified {beautified} JavaScript files")

    def run_semgrep(self):
        """Run Semgrep security analysis"""
        print_section("Running Semgrep Security Scan")

        beautified_dir = self.output_dir / "beautified_js"
        semgrep_dir = self.output_dir / "semgrep"
        semgrep_dir.mkdir(exist_ok=True)

        js_files = list(beautified_dir.glob("*.js"))
        if not js_files:
            print_warning("No JavaScript files to scan with Semgrep")
            return

        abs_scan_dir = beautified_dir.resolve()

        print_info("Running Semgrep with multiple security rulesets...")
        print_info("This may take several minutes...")

        script_dir = Path(__file__).resolve().parent
        custom_cfg = (script_dir / "semgrep_custom.yml").resolve()

        try:
            cmd = [
                'docker', 'run', '--rm',
                '-v', f'{abs_scan_dir}:/src',
                '-v', f'{custom_cfg}:/semgrep_custom.yml:ro',
                'semgrep/semgrep',
                'semgrep', 'scan',
                '--config', 'p/default',
                '--config', 'p/secrets',
                '--config', 'p/owasp-top-ten',
                '--config', 'p/cwe-top-25',
                '--config', 'p/security-audit',
                '--config', 'p/findsecbugs',
                '--config', 'p/typescript',
                '--config', 'p/xss',
                '--config', 'p/javascript',
                '--config', '/semgrep_custom.yml',
                '--max-target-bytes', '50000000',
                '--json'
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

            if result.stdout:
                with open(semgrep_dir / "semgrep_results.json", 'w', encoding='utf-8', errors='replace') as f:
                    f.write(result.stdout)

                try:
                    data = json.loads(result.stdout)
                    findings = data.get('results', [])
                    errors = data.get('errors', [])

                    print_success(f"Semgrep found {len(findings)} security findings")

                    if errors:
                        print_warning(f"Semgrep reported {len(errors)} errors/timeouts")

                    severity_counts = {}
                    for finding in findings:
                        severity = finding.get('extra', {}).get('severity', 'UNKNOWN')
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    if severity_counts:
                        print_info("Findings by severity:")
                        for severity, count in sorted(severity_counts.items()):
                            print(f"  {severity}: {count}")

                except json.JSONDecodeError:
                    print_warning("Could not parse Semgrep JSON output")

            with open(semgrep_dir / "semgrep_output.log", 'w', encoding='utf-8', errors='replace') as f:
                f.write(result.stdout or "")
                f.write(result.stderr or "")

            print_info("Generating human-readable report...")
            cmd_text = cmd[:-1]  # Remove --json
            result_text = subprocess.run(cmd_text, capture_output=True, text=True, timeout=600)

            with open(semgrep_dir / "semgrep_report.txt", 'w', encoding='utf-8', errors='replace') as f:
                f.write(result_text.stdout or "")
                f.write(result_text.stderr or "")

            print_success("Semgrep analysis complete")

        except subprocess.TimeoutExpired:
            print_error("Semgrep analysis timed out")
        except Exception as e:
            print_error(f"Semgrep analysis failed: {e}")

    # ---------------------------------
    # FIXED: TruffleHog output streaming
    # ---------------------------------
    def run_trufflehog(self):
        """Run TruffleHog secret scanning (stream stdout to file reliably)."""
        print_section("Running TruffleHog Secret Scanning")

        beautified_dir = self.output_dir / "beautified_js"
        trufflehog_dir = self.output_dir / "trufflehog"
        trufflehog_dir.mkdir(exist_ok=True)

        js_files = list(beautified_dir.glob("*.js"))
        if not js_files:
            print_warning("No JavaScript files to scan with TruffleHog")
            return

        abs_scan_dir = beautified_dir.resolve()
        print_info("Scanning for secrets with TruffleHog (Docker)...")
        print_info(f"Scanning directory: {abs_scan_dir}")

        output_file = trufflehog_dir / "trufflehog_results.json"   # JSONL output, name kept for compatibility
        stderr_file = trufflehog_dir / "trufflehog_stderr.log"

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{abs_scan_dir}:/pwd",
            "trufflesecurity/trufflehog:latest",
            "filesystem", "/pwd/",
            "--json"
        ]

        total_findings = 0
        file_findings = {}

        try:
            with open(output_file, "w", encoding="utf-8", errors="replace") as out_f, \
                 open(stderr_file, "w", encoding="utf-8", errors="replace") as err_f:

                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )

                start = datetime.now()
                timeout_seconds = 300

                # Stream stdout line-by-line into file while also counting/parsing
                while True:
                    elapsed = (datetime.now() - start).total_seconds()
                    if elapsed > timeout_seconds:
                        proc.kill()
                        raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout_seconds)

                    line = proc.stdout.readline() if proc.stdout else ""
                    if line:
                        out_f.write(line)

                        s = line.strip()
                        if s:
                            total_findings += 1
                            try:
                                finding = json.loads(s)
                                source_file = (
                                    finding.get("SourceMetadata", {})
                                    .get("Data", {})
                                    .get("Filesystem", {})
                                    .get("file", "unknown")
                                )
                                source_file = os.path.basename(source_file)
                                file_findings[source_file] = file_findings.get(source_file, 0) + 1
                            except Exception:
                                pass
                        continue

                    if proc.poll() is not None:
                        break

                # Drain remaining stderr
                if proc.stderr:
                    err = proc.stderr.read()
                    if err:
                        err_f.write(err)

                rc = proc.returncode

            if rc == 0:
                if total_findings > 0:
                    print_success(f"TruffleHog found {total_findings} potential secrets")
                    if file_findings:
                        print_info("Secrets found per file:")
                        for fn, cnt in sorted(file_findings.items(), key=lambda x: x[1], reverse=True):
                            print(f"  {fn}: {cnt}")
                else:
                    print_success("TruffleHog found 0 secrets")
            else:
                print_warning(f"TruffleHog exited with code {rc}. Check: {stderr_file}")

            print_success(f"TruffleHog results saved to: {output_file}")
            print_info(f"TruffleHog stderr log saved to: {stderr_file}")

        except subprocess.TimeoutExpired:
            print_error("TruffleHog scan timed out")
        except Exception as e:
            print_error(f"TruffleHog scan failed: {e}")

    def generate_summary(self):
        """Generate analysis summary"""
        print_section("Generating Analysis Summary")

        summary_file = self.output_dir / "ANALYSIS_SUMMARY.txt"

        with open(summary_file, 'w', encoding='utf-8', errors='replace') as f:
            f.write("╔════════════════════════════════════════════════════════════════╗\n")
            f.write("║          JavaScript Security Analysis Summary                  ║\n")
            f.write("╚════════════════════════════════════════════════════════════════╝\n\n")
            f.write(f"Analysis Date: {datetime.now()}\n")
            f.write(f"Target URL: {self.base_url}\n")
            f.write(f"Spider Depth: {self.depth}\n")
            f.write(f"Output Directory: {self.output_dir}\n\n")
            f.write("─" * 64 + "\n\n")

            # File counts
            f.write("FILES ANALYZED:\n")
            original_count = len(list((self.output_dir / "original_js").glob("*.js")))
            beautified_count = len(list((self.output_dir / "beautified_js").glob("*.js")))
            original_html_count = len(list((self.output_dir / "original_html").glob("*.html")))
            beautified_html_count = len(list((self.output_dir / "beautified_html").glob("*.html")))

            f.write(f"  - JavaScript URLs discovered: {len(self.js_urls)}\n")
            f.write(f"  - Pages visited: {len(self.visited_urls)}\n")
            f.write(f"  - Original JS files: {original_count}\n")
            f.write(f"  - Beautified JS files: {beautified_count}\n")
            f.write(f"  - Original HTML files: {original_html_count}\n")
            f.write(f"  - Beautified HTML files: {beautified_html_count}\n\n")

            # Analysis results
            f.write("ANALYSIS RESULTS:\n")

            semgrep_dir = self.output_dir / "semgrep"
            if semgrep_dir.exists():
                f.write(f"  ✓ Semgrep: {semgrep_dir}/\n")
            else:
                f.write("  ✗ Semgrep: Skipped\n")

            trufflehog_dir = self.output_dir / "trufflehog"
            if trufflehog_dir.exists():
                f.write(f"  ✓ TruffleHog: {trufflehog_dir}/\n")
            else:
                f.write("  ✗ TruffleHog: Skipped\n")

            f.write("\n" + "─" * 64 + "\n\n")
            f.write("Review the individual tool outputs for detailed findings.\n")

        # Print summary to console
        with open(summary_file, 'r', encoding='utf-8', errors='replace') as f:
            print(f.read())

        print_success(f"Summary saved to: {summary_file}")

    def run_analysis(self):
        """Main analysis workflow"""
        print_banner()

        print_info(f"Target URL: {self.base_url}")
        print_info(f"Output directory: {self.output_dir}")
        print_info(f"Spider depth: {self.depth}")

        # Setup browser
        self.setup_driver()

        # Spider and extract JS
        print_section("Crawling Website for JavaScript Files")
        self.spider_pages(self.base_url, self.depth)

        # NEW: Save root HTML + beautify later
        self.download_root_html()

        # Close browser
        if self.driver:
            self.driver.quit()

        print_success(f"Found {len(self.js_urls)} unique JavaScript URLs")

        # Save JS URLs
        urls_file = self.output_dir / "js_urls.txt"
        with open(urls_file, 'w', encoding='utf-8', errors='replace') as f:
            for url in sorted(self.js_urls):
                f.write(url + '\n')
        print_info(f"JavaScript URLs saved to: {urls_file}")

        # Download JS files
        self.download_js_files()

        # Beautify JS files
        self.beautify_js_files()

        # NEW: Beautify HTML files
        self.beautify_html_files()

        # Run security tools
        if not self.skip_semgrep:
            self.run_semgrep()
        else:
            print_warning("Skipping Semgrep analysis")

        if not self.skip_trufflehog:
            self.run_trufflehog()
        else:
            print_warning("Skipping TruffleHog analysis")

        # Generate summary
        self.generate_summary()

        print_section("Analysis Complete!")
        print_success(f"All results saved to: {self.output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="JavaScript Security Analyzer - Crawl, extract, and analyze JavaScript files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com
  %(prog)s --url https://example.com --depth 2 --output my_analysis
  %(prog)s --url https://example.com --skip-semgrep

Requirements:
  - Chrome/Chromium browser
  - chromedriver
  - js-beautify (npm install -g js-beautify)
  - docker (for Semgrep and TruffleHog)
  - Python packages: selenium, beautifulsoup4, requests, tldextract
        """
    )

    parser.add_argument("--url", required=True, help="URL of the website to analyze")
    parser.add_argument("--output", "-o", help="Output directory (default: js_analysis_TIMESTAMP)")
    parser.add_argument("--depth", "-d", type=int, default=1, help="Spider depth (default: 1)")
    parser.add_argument("--skip-semgrep", "-s", action="store_true", help="Skip Semgrep analysis")
    parser.add_argument("--skip-trufflehog", "-t", action="store_true", help="Skip TruffleHog analysis")

    args = parser.parse_args()

    # Set default output directory
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"js_analysis_{timestamp}"

    try:
        analyzer = JSSecurityAnalyzer(
            url=args.url,
            output_dir=args.output,
            depth=args.depth,
            skip_semgrep=args.skip_semgrep,
            skip_trufflehog=args.skip_trufflehog
        )

        analyzer.run_analysis()

    except KeyboardInterrupt:
        print_error("\nAnalysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print_error(f"Analysis failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
