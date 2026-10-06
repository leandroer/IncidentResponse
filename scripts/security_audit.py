#!/usr/bin/env python3
"""Dependency-free security checks for the repository's static browser content."""

from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_CSP = (
    "default-src 'self'; style-src 'self'; script-src 'self'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'none'; "
    "object-src 'none'; base-uri 'self'; form-action 'none'; "
    "upgrade-insecure-requests"
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line: int
    name: str
    reason: str


def display_path(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


class HTMLSecurityAudit(HTMLParser):
    """Inspect markup while retaining source line numbers for findings."""

    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.findings: list[Finding] = []
        self.csp_values: list[str] = []

    def report(self, name: str, reason: str) -> None:
        self.findings.append(Finding(self.path, self.getpos()[0], name, reason))

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attributes = {name.lower(): value or "" for name, value in attrs}

        if tag == "meta" and attributes.get("http-equiv", "").lower() == "content-security-policy":
            self.csp_values.append(attributes.get("content", ""))

        for name, value in attributes.items():
            if name.startswith("on"):
                self.report("inline-event-handler", f"inline JavaScript handler {name!r} bypasses script-src")
            if value.lstrip().lower().startswith("javascript:"):
                self.report("javascript-url", f"{name!r} contains a javascript: URL")

        if tag == "script":
            source = attributes.get("src")
            if source:
                if is_external_url(source):
                    self.report("external-script", f"script source is not a local same-origin path: {source}")
            else:
                self.report("inline-script", "inline scripts are blocked by the site's restrictive CSP")

        if tag == "link" and "stylesheet" in attributes.get("rel", "").lower().split():
            href = attributes.get("href", "")
            if is_external_url(href):
                self.report("external-stylesheet", f"stylesheet is not a local same-origin path: {href}")

        for attribute in ("src", "href", "action", "formaction", "poster", "data"):
            value = attributes.get(attribute, "").strip().lower()
            if value.startswith("http://"):
                self.report("insecure-resource", f"{attribute!r} loads an insecure HTTP resource")

        if tag in {"iframe", "embed", "object"}:
            self.report("embedded-content", f"unexpected <{tag}> content can create an external security boundary")


def is_external_url(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith(("http://", "https://", "//"))


def mask_javascript_literals(source: str) -> str:
    """Mask comments and strings while preserving newlines and source positions."""
    output = list(source)
    index = 0
    state = "code"
    quote = ""
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "code":
            if character == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if character == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if character in {"'", '"', "`"}:
                quote = character
                output[index] = " "
                index += 1
                state = "string"
                continue
        elif state == "line-comment":
            if character == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        elif state == "block-comment":
            if character == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if character != "\n":
                output[index] = " "
            index += 1
            continue
        elif state == "string":
            if character == "\\":
                output[index] = " "
                if index + 1 < len(source):
                    if source[index + 1] != "\n":
                        output[index + 1] = " "
                    index += 2
                    continue
            if character == quote:
                output[index] = " "
                state = "code"
            elif character != "\n":
                output[index] = " "
            index += 1
            continue
        index += 1
    return "".join(output)


JAVASCRIPT_RULES = (
    ("innerHTML", re.compile(r"\binnerHTML\b"), "HTML-string assignment can create DOM injection"),
    ("outerHTML", re.compile(r"\bouterHTML\b"), "HTML-string assignment can create DOM injection"),
    ("insertAdjacentHTML", re.compile(r"\binsertAdjacentHTML\s*\("), "parses a string as active HTML"),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("), "writes untrusted markup into the document"),
    ("eval", re.compile(r"(?:^|[^.\w])eval\s*\("), "executes a string as JavaScript"),
    ("dynamic-Function", re.compile(r"\b(?:new\s+)?Function\s*\("), "constructs executable code from strings"),
    ("fetch", re.compile(r"\bfetch\s*\("), "unexpected browser network request"),
    ("XMLHttpRequest", re.compile(r"\bXMLHttpRequest\b"), "unexpected browser network request"),
    ("WebSocket", re.compile(r"\bWebSocket\s*\("), "unexpected persistent browser network connection"),
    ("EventSource", re.compile(r"\bEventSource\s*\("), "unexpected server-sent-event connection"),
    ("sendBeacon", re.compile(r"\b(?:navigator\s*\.\s*)?sendBeacon\s*\("), "unexpected browser data transmission"),
    ("localStorage", re.compile(r"\blocalStorage\b"), "unexpected persistent browser storage"),
    ("sessionStorage", re.compile(r"\bsessionStorage\b"), "unexpected browser session storage"),
    ("indexedDB", re.compile(r"\bindexedDB\b"), "unexpected browser database storage"),
    ("URLSearchParams", re.compile(r"\bURLSearchParams\b"), "URL parameters require explicit validation before DOM use"),
    ("location.search", re.compile(r"\b(?:window\s*\.\s*)?location\s*\.\s*search\b"), "query-string input requires validation"),
    ("location.hash", re.compile(r"\b(?:window\s*\.\s*)?location\s*\.\s*hash\b"), "URL-fragment input requires validation"),
)


def audit_html(path: Path) -> list[Finding]:
    parser = HTMLSecurityAudit(path)
    try:
        parser.feed(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        return [Finding(path, 1, "unreadable-html", f"cannot safely inspect file: {error}")]

    if not parser.csp_values:
        parser.findings.append(Finding(path, 1, "missing-csp", "production HTML must declare the restrictive CSP"))
    elif len(parser.csp_values) != 1:
        parser.findings.append(Finding(path, 1, "duplicate-csp", "exactly one CSP meta policy is expected"))
    elif parser.csp_values[0] != EXPECTED_CSP:
        parser.findings.append(Finding(path, 1, "unexpected-csp", "CSP differs from the approved restrictive baseline"))
    return parser.findings


def audit_javascript(path: Path) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        return [Finding(path, 1, "unreadable-javascript", f"cannot safely inspect file: {error}")]

    masked = mask_javascript_literals(source)
    findings: list[Finding] = []
    for name, pattern, reason in JAVASCRIPT_RULES:
        for match in pattern.finditer(masked):
            line = masked.count("\n", 0, match.start()) + 1
            findings.append(Finding(path, line, name, reason))
    return findings


def tracked_source_files(suffix: str) -> list[Path]:
    ignored_parts = {".git", "node_modules", "vendor"}
    return sorted(
        path
        for path in ROOT.rglob(f"*{suffix}")
        if path.is_file() and not ignored_parts.intersection(path.relative_to(ROOT).parts)
    )


def main() -> int:
    html_files = tracked_source_files(".html")
    javascript_files = tracked_source_files(".js")
    findings: list[Finding] = []

    for path in html_files:
        findings.extend(audit_html(path))
    for path in javascript_files:
        findings.extend(audit_javascript(path))

    if findings:
        for finding in sorted(findings, key=lambda item: (display_path(item.path), item.line, item.name)):
            print(f"{display_path(finding.path)}:{finding.line}: {finding.name}: {finding.reason}")
        print(f"Security audit failed with {len(findings)} finding(s).", file=sys.stderr)
        return 1

    print(
        f"Security audit passed for {len(html_files)} HTML file(s) "
        f"and {len(javascript_files)} JavaScript file(s)."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
