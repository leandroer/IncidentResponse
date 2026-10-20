"""Bounded HTTPS-only link checks; distinguish broken from inconclusive."""
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

def validate_url(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('only credential-free HTTPS public URLs are allowed')
    addresses = socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(item[4][0]).is_global for item in addresses):
        raise ValueError('link target must resolve only to public IP addresses')

class PublicHTTPSRedirects(HTTPRedirectHandler):
    max_redirections = 5
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)

def check_url(url, attempts=3):
    opener = build_opener(PublicHTTPSRedirects())
    method = 'HEAD'
    for attempt in range(attempts):
        try:
            validate_url(url)
            headers = {'User-Agent':'IR-Framework-Link-Audit/1.1'}
            if method == 'GET':
                headers['Range'] = 'bytes=0-0'
            request = Request(url, headers=headers, method=method)
            with opener.open(request, timeout=15) as response:
                # Do not download or print response bodies.
                return 'verified', f'HTTP {response.status}'
        except HTTPError as error:
            if error.code in (404, 410):
                return 'broken', f'HTTP {error.code}'
            if error.code in (405, 501) and method == 'HEAD':
                method = 'GET'
            elif error.code in (401, 403):
                return 'inconclusive', f'HTTP {error.code}: authentication or bot protection'
            elif error.code == 429 or error.code >= 500:
                if attempt + 1 == attempts:
                    return ('inconclusive' if error.code == 429 else 'broken'), f'HTTP {error.code} after retries'
            else:
                return 'inconclusive', f'HTTP {error.code}'
        except ValueError as error:
            return 'broken', str(error)
        except (URLError, TimeoutError, OSError):
            if attempt + 1 == attempts:
                return 'inconclusive', 'network/TLS timeout or DNS failure after retries'
        if attempt + 1 < attempts:
            time.sleep(2 ** attempt)
    return 'inconclusive', 'request method could not be verified'

def check_urls(urls):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(zip(urls, pool.map(check_url, urls)))
