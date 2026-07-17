#!/usr/bin/env python3
"""Dependency-free structural and safety checks for the static site."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from concurrent.futures import ThreadPoolExecutor
import sys

ROOT = Path(__file__).resolve().parents[1]
PAGES = [ROOT / name for name in ("index.html", "detection.html", "response.html", "playbooks.html", "resources.html", "404.html")]
EXTERNALS = set()

class PageAudit(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids, self.hrefs, self.headings, self.errors = set(), [], [], []
        self.description = self.csp = self.canonical = self.favicon = False
        self.nav_label = self.main_id = self.skip_link = False
        self.tables = self.captions = self.th = self.scoped_th = 0

    def handle_starttag(self, tag, attrs):
        data = dict(attrs)
        identifier = data.get("id")
        if identifier:
            if identifier in self.ids: self.errors.append(f"duplicate id #{identifier}")
            self.ids.add(identifier)
        if tag == "meta" and data.get("name") == "description": self.description = True
        if tag == "meta" and data.get("http-equiv", "").lower() == "content-security-policy": self.csp = True
        if tag == "link" and data.get("rel") == "canonical": self.canonical = True
        if tag == "link" and data.get("rel") == "icon": self.favicon = True
        if tag == "nav" and data.get("aria-label"): self.nav_label = True
        if tag == "main" and identifier == "main-content": self.main_id = True
        if tag == "a":
            href = data.get("href", "")
            self.hrefs.append((href, data))
            if href == "#main-content": self.skip_link = True
            if data.get("target") == "_blank" and not {"noopener", "noreferrer"}.issubset(set(data.get("rel", "").split())):
                self.errors.append(f"unsafe new-tab link: {href}")
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}: self.headings.append(int(tag[1]))
        if tag == "table": self.tables += 1
        if tag == "caption": self.captions += 1
        if tag == "th":
            self.th += 1
            if data.get("scope") in {"col", "row"}: self.scoped_th += 1
        if "style" in data: self.errors.append(f"inline style on <{tag}>")

def audit(path):
    parser = PageAudit()
    parser.feed(path.read_text(encoding="utf-8"))
    required = {"description": parser.description, "CSP": parser.csp, "favicon": parser.favicon,
                "labeled navigation": parser.nav_label, "main landmark": parser.main_id, "skip link": parser.skip_link}
    if path.name != "404.html": required["canonical"] = parser.canonical
    parser.errors.extend(f"missing {name}" for name, present in required.items() if not present)
    if parser.headings.count(1) != 1: parser.errors.append("page must contain exactly one h1")
    for current, following in zip(parser.headings, parser.headings[1:]):
        if following > current + 1: parser.errors.append(f"heading skips h{current} to h{following}")
    if parser.tables != parser.captions: parser.errors.append("every table requires a caption")
    if parser.th != parser.scoped_th: parser.errors.append("every table header requires scope")
    for href, _ in parser.hrefs:
        if href.startswith("https://"):
            EXTERNALS.add(href)
            continue
        if not href or href.startswith("mailto:"): continue
        if href.startswith("#"):
            if href[1:] not in parser.ids: parser.errors.append(f"missing fragment target {href}")
            continue
        target = href.split("#", 1)[0]
        if not target: continue
        resolved = (path.parent / target).resolve()
        if not resolved.exists(): parser.errors.append(f"missing local target {href}")
    return parser.errors

failures = []
for page in PAGES:
    if not page.exists(): failures.append(f"{page.name}: missing page"); continue
    failures.extend(f"{page.name}: {problem}" for problem in audit(page))

if failures:
    print("\n".join(failures))
    sys.exit(1)
print(f"Site audit passed for {len(PAGES)} pages.")

if "--external" in sys.argv:
    def check_url(url):
        try:
            request = Request(url, headers={"User-Agent": "IR-Framework-Link-Audit/1.0"}, method="HEAD")
            with urlopen(request, timeout=20) as response:
                return None if response.status < 400 else f"{response.status} {url}"
        except HTTPError as error:
            # Authentication, rate limiting, and bot protection still prove the host/path responded.
            return f"{error.code} {url}" if error.code in {404, 410} or error.code >= 500 else None
        except URLError as error:
            return f"unreachable {url}: {error.reason}"

    with ThreadPoolExecutor(max_workers=12) as pool:
        external_failures = [result for result in pool.map(check_url, sorted(EXTERNALS)) if result]
    if external_failures:
        print("\n".join(external_failures))
        sys.exit(1)
    print(f"External link audit passed for {len(EXTERNALS)} URLs.")
