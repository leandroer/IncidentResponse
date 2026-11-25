"""Bounded HTTPS-only link checks over validated public socket addresses."""
from concurrent.futures import ThreadPoolExecutor
from http.client import HTTPException, HTTPSConnection
import ipaddress
import socket
import time
from urllib.parse import urljoin, urlsplit

_REDIRECTS = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5
_TIMEOUT = 15
_IPV6_TRANSITION = tuple(map(ipaddress.ip_network, (
    '64:ff9b::/96', '64:ff9b:1::/48', '2001::/32', '2002::/16',
)))


def public_addresses(host):
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError('link target must resolve to a public IP address')
    for family, _, _, _, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if (family not in (socket.AF_INET, socket.AF_INET6)
                or not address.is_global or address.is_multicast
                or (address.version == 6 and (
                    address.is_site_local
                    or address.ipv4_mapped is not None
                    or sockaddr[3]
                    or any(address in network for network in _IPV6_TRANSITION)
                ))):
            raise ValueError('link target must resolve only to public IP addresses')
    return addresses


class PublicHTTPSConnection(HTTPSConnection):
    def connect(self):
        # Connect to the exact numeric sockaddr returned and approved above.
        # Do not pass the hostname back to another resolver or a proxy.
        addresses = public_addresses(self.host)
        last_error = None
        for family, kind, protocol, _, sockaddr in addresses:
            with socket.socket(family, kind, protocol) as raw:
                raw.settimeout(self.timeout)
                try:
                    raw.connect(sockaddr)
                except OSError as error:
                    last_error = error
                    continue
                # The original hostname remains the TLS identity and HTTP Host.
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
        raise last_error


def request_status(url, method):
    headers = {'User-Agent': 'IR-Framework-Link-Audit/1.2'}
    if method == 'GET':
        headers['Range'] = 'bytes=0-0'

    for hop in range(_MAX_REDIRECTS + 1):
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.port not in (None, 443)):
            raise ValueError('only credential-free HTTPS public URLs are allowed')
        host = parsed.hostname.encode('idna').decode('ascii')
        target = parsed.path or '/'
        if parsed.query:
            target += '?' + parsed.query
        connection = PublicHTTPSConnection(host, port=443, timeout=_TIMEOUT)
        try:
            connection.request(method, target, headers=headers)
            with connection.getresponse() as response:
                status = response.status
                location = response.getheader('Location')
        finally:
            connection.close()

        if status not in _REDIRECTS or not location:
            return status
        if hop == _MAX_REDIRECTS:
            raise ValueError('HTTPS redirect limit exceeded')
        url = urljoin(url, location)


def check_url(url, attempts=3):
    method = 'HEAD'
    for attempt in range(attempts):
        try:
            status = request_status(url, method)
        except ValueError as error:
            # Private/synthetic DNS may be a VPN artifact, not a dead link.
            return 'inconclusive', 'blocked by safe-target policy: ' + str(error)
        except (OSError, HTTPException):
            if attempt + 1 == attempts:
                return 'inconclusive', 'network/TLS timeout or DNS failure after retries'
        else:
            if 200 <= status < 300:
                return 'verified', f'HTTP {status}'
            if status in (404, 410):
                return 'broken', f'HTTP {status}'
            if status in (405, 501) and method == 'HEAD':
                method = 'GET'
            elif status in (401, 403):
                return 'inconclusive', f'HTTP {status}: authentication or bot protection'
            elif status == 429 or status >= 500:
                if attempt + 1 == attempts:
                    return ('inconclusive' if status == 429 else 'broken'), f'HTTP {status} after retries'
            else:
                return 'inconclusive', f'HTTP {status}'
        if attempt + 1 < attempts:
            time.sleep(2 ** attempt)
    return 'inconclusive', 'request method could not be verified'


def check_urls(urls):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(zip(urls, pool.map(check_url, urls)))
