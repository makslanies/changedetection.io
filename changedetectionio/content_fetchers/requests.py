from flask_babel import lazy_gettext as _l
from loguru import logger
from urllib.parse import urljoin, urlparse
import hashlib
import os
import re
import asyncio

from changedetectionio import strtobool
from changedetectionio.content_fetchers.exceptions import BrowserStepsInUnsupportedFetcher, EmptyReply, Non200ErrorCodeReceived
from changedetectionio.content_fetchers.base import Fetcher
from changedetectionio.validate_url import is_fetch_url_allowed, is_private_hostname, is_url_private_or_parser_confused


# "html_requests" is listed as the default fetcher in store.py!
class fetcher(Fetcher):
    fetcher_description = _l("Basic fast Plaintext/HTTP Client")
    supports_pdf = True

    def __init__(self, proxy_override=None, custom_browser_connection_url=None, **kwargs):
        super().__init__(**kwargs)
        self.proxy_override = proxy_override
        # browser_connection_url is none because its always 'launched locally'

    def _run_sync(self,
            url,
            timeout,
            request_headers,
            request_body,
            request_method,
            ignore_status_codes=False,
            current_include_filters=None,
            is_binary=False,
            empty_pages_are_a_change=False,
            watch_uuid=None,
            fetch_favicon=True,
            ):
        """Synchronous version of run - the original requests implementation"""

        import chardet
        import requests
        from requests.exceptions import ProxyError, ConnectionError, RequestException

        if self.browser_steps:
            raise BrowserStepsInUnsupportedFetcher(url=url)

        proxies = {}

        # Allows override the proxy on a per-request basis
        # https://requests.readthedocs.io/en/latest/user/advanced/#socks
        # Should also work with `socks5://user:pass@host:port` type syntax.

        if self.proxy_override:
            proxies = {'http': self.proxy_override, 'https': self.proxy_override, 'ftp': self.proxy_override}
        else:
            if self.system_http_proxy:
                proxies['http'] = self.system_http_proxy
            if self.system_https_proxy:
                proxies['https'] = self.system_https_proxy

        session = requests.Session()

        # Configure retry adapter for low-level network errors only
        # Retries connection timeouts, read timeouts, connection resets - not HTTP status codes
        # Especially helpful in parallel test execution when servers are slow/overloaded
        # Configurable via REQUESTS_RETRY_MAX_COUNT (default: 3 attempts)
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        max_retries = int(os.getenv("REQUESTS_RETRY_MAX_COUNT", "6"))
        retry_strategy = Retry(
            total=max_retries,
            connect=max_retries,  # Retry connection timeouts
            read=max_retries,     # Retry read timeouts
            status=0,             # Don't retry on HTTP status codes
            backoff_factor=0.5,   # Wait 0.3s, 0.6s, 1.2s between retries
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            raise_on_status=False
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        if strtobool(os.getenv('ALLOW_FILE_URI', 'false')) and url.startswith('file://'):
            from requests_file import FileAdapter
            session.mount('file://', FileAdapter())

        allow_iana_restricted = strtobool(os.getenv('ALLOW_IANA_RESTRICTED_ADDRESSES', 'false'))

        try:
            # Fresh DNS check at fetch time — catches DNS rebinding regardless of add-time cache.
            # Shared with every other fetch entry point, so the scheme allowlist and the
            # parser-differential rejection (GHSA-rph4-96w6-q594) stay in step here too.
            # Per-redirect-hop re-validation is done separately in the loop below.
            ok, reason = is_fetch_url_allowed(url)
            if not ok:
                raise Exception(reason)

            r = session.request(method=request_method,
                                data=request_body.encode('utf-8') if type(request_body) is str else request_body,
                                url=url,
                                headers=request_headers,
                                timeout=timeout,
                                proxies=proxies,
                                verify=False,
                                allow_redirects=False)

            # Manually follow redirects so each hop's resolved IP can be validated,
            # preventing SSRF via an open redirect on a public host.
            current_url = url
            for _ in range(10):
                if not r.is_redirect:
                    break
                location = r.headers.get('Location', '')
                redirect_url = urljoin(current_url, location)
                if not allow_iana_restricted:
                    if is_url_private_or_parser_confused(redirect_url):
                        raise Exception(f"Redirect blocked: '{redirect_url}' resolves to a private/reserved IP address "
                                        f"or contains a parser-differential payload.")
                current_url = redirect_url
                r = session.request('GET', redirect_url,
                                    headers=request_headers,
                                    timeout=timeout,
                                    proxies=proxies,
                                    verify=False,
                                    allow_redirects=False)
            else:
                raise Exception("Too many redirects")

        except Exception as e:
            msg = str(e)
            if proxies and 'SOCKSHTTPSConnectionPool' in msg:
                msg = f"Proxy connection failed? {msg}"
            raise Exception(msg) from e

        # If the response did not tell us what encoding format to expect, Then use chardet to override what `requests` thinks.
        # For example - some sites don't tell us it's utf-8, but return utf-8 content
        # This seems to not occur when using webdriver/selenium, it seems to detect the text encoding more reliably.
        # https://github.com/psf/requests/issues/1604 good info about requests encoding detection
        if not is_binary:
            # Don't run this for PDF (and requests identified as binary) takes a _long_ time
            if not r.headers.get('content-type') or not 'charset=' in r.headers.get('content-type'):
                # For XML/RSS feeds, check the XML declaration for encoding attribute
                # This is more reliable than chardet which can misdetect UTF-8 as MacRoman
                content_type = r.headers.get('content-type', '').lower()
                if 'xml' in content_type or 'rss' in content_type:
                    # Look for <?xml version="1.0" encoding="UTF-8"?>
                    xml_encoding_match = re.search(rb'<\?xml[^>]+encoding=["\']([^"\']+)["\']', r.content[:200])
                    if xml_encoding_match:
                        r.encoding = xml_encoding_match.group(1).decode('ascii')
                    else:
                        # Default to UTF-8 for XML if no encoding found
                        r.encoding = 'utf-8'
                else:
                    # No charset in HTTP header - sniff encoding in priority order matching browsers
                    # (WHATWG encoding sniffing algorithm):
                    # 1. BOM - highest confidence, check before anything else
                    # 2. <meta charset> in first 2kb
                    # 3. chardet statistical detection - last resort
                    # See: https://github.com/dgtlmoon/changedetection.io/issues/3952
                    boms = [
                        (b'\xef\xbb\xbf', 'utf-8-sig'),
                        (b'\xff\xfe', 'utf-16-le'),
                        (b'\xfe\xff', 'utf-16-be'),
                    ]
                    bom_encoding = next((enc for bom, enc in boms if r.content.startswith(bom)), None)
                    if bom_encoding:
                        logger.info(f"URL: {url} Using encoding '{bom_encoding}' detected from BOM")
                        r.encoding = bom_encoding
                    else:
                        meta_charset_match = re.search(rb'<meta[^>]+charset\s*=\s*["\']?\s*([^"\'\s;>]+)', r.content[:2000], re.IGNORECASE)
                        if meta_charset_match:
                            encoding = meta_charset_match.group(1).decode('ascii', errors='ignore')
                            logger.info(f"URL: {url} No content-type encoding in HTTP headers - Using encoding '{encoding}' from HTML meta charset tag")
                            r.encoding = encoding
                        else:
                            encoding = chardet.detect(r.content)['encoding']
                            logger.warning(f"URL: {url} No charset in headers or meta tag, guessed encoding as '{encoding}' via chardet")
                            if encoding:
                                r.encoding = encoding

        self.headers = r.headers

        if not r.content or not len(r.content):
            logger.debug(f"Requests returned empty content for '{url}'")
            if not empty_pages_are_a_change:
                raise EmptyReply(url=url, status_code=r.status_code)
            else:
                logger.debug(f"URL {url} gave zero byte content reply with Status Code {r.status_code}, but empty_pages_are_a_change = True")

        # @todo test this
        # @todo maybe you really want to test zero-byte return pages?
        if r.status_code != 200 and not ignore_status_codes:
            # maybe check with content works?
            raise Non200ErrorCodeReceived(url=url, status_code=r.status_code, page_html=r.text)

        self.status_code = r.status_code
        if is_binary:
            # Binary files just return their checksum until we add something smarter
            self.content = hashlib.md5(r.content).hexdigest()
        else:
            self.content = r.text

        self.raw_content = r.content

        if fetch_favicon and not is_binary and self.content:
            try:
                self._fetch_favicon(
                    session=session,
                    page_url=current_url,
                    html=self.content,
                    proxies=proxies,
                    timeout=timeout,
                    request_headers=request_headers,
                    allow_iana_restricted=allow_iana_restricted,
                )
            except Exception as e:
                logger.debug(f"Favicon fetch skipped for '{url}': {e}")

        # If the content is an image, set it as screenshot for SSIM/visual comparison
        content_type = r.headers.get('content-type', '').lower()
        if 'image/' in content_type:
            self.screenshot = r.content
            logger.debug(f"Image content detected ({content_type}), set as screenshot for comparison")

        return None

    def _fetch_favicon(self, session, page_url, html, proxies, timeout, request_headers, allow_iana_restricted):
        """Download the page's icon for the plain HTTP fetcher.

        Browser fetchers already do this in-page. html_requests never did, so the
        watch list kept the empty circle placeholder forever.
        """
        import base64

        from bs4 import BeautifulSoup

        def icon_links(markup, base_url):
            found = []
            soup = BeautifulSoup(markup[:200000], 'html.parser')
            for link in soup.find_all('link'):
                rels = link.get('rel') or []
                rel = ' '.join(rels).lower() if isinstance(rels, list) else str(rels).lower()
                if 'icon' not in rel:
                    continue
                href = (link.get('href') or '').strip()
                if not href:
                    continue
                size = 16
                sizes = (link.get('sizes') or '').lower()
                if 'x' in sizes:
                    try:
                        size = int(sizes.split('x', 1)[0])
                    except ValueError:
                        size = 16
                elif 'apple-touch-icon' in rel:
                    size = 180
                found.append((size, 'apple-touch-icon' in rel, urljoin(base_url, href)))
            return found

        def try_icons(candidates, referer_host):
            candidates = sorted(candidates, key=lambda item: (item[0], item[1]), reverse=True)
            for _size, _apple, icon_url in candidates[:6]:
                if icon_url.startswith('data:'):
                    blob = self._favicon_from_data_uri(icon_url)
                    if blob:
                        self.favicon_blob = blob
                        return True
                    continue

                ok, _reason = is_fetch_url_allowed(icon_url)
                if not ok:
                    continue

                headers = {}
                if urlparse(icon_url).netloc == referer_host and isinstance(request_headers, dict):
                    headers = dict(request_headers)
                elif isinstance(request_headers, dict) and request_headers.get('User-Agent'):
                    headers = {'User-Agent': request_headers['User-Agent']}

                try:
                    response = self._get_with_redirect_checks(
                        session, icon_url, headers, proxies, budget, allow_iana_restricted
                    )
                except Exception as e:
                    logger.debug(f"Favicon candidate failed {icon_url}: {e}")
                    continue

                if response is None or response.status_code != 200 or not response.content:
                    continue
                if len(response.content) > 1024 * 1024:
                    continue
                mime = (response.headers.get('content-type') or '').split(';', 1)[0].strip().lower()
                if mime and not mime.startswith('image/') and mime not in ('application/octet-stream', 'application/ico', 'image/vnd.microsoft.icon'):
                    continue
                self.favicon_blob = {
                    'url': icon_url,
                    'base64': base64.b64encode(response.content).decode('ascii'),
                    'mime_type': mime or None,
                }
                return True
            return False

        page_host = urlparse(page_url).netloc
        budget = min(int(timeout or 8), 8)
        head = html[:30000]

        # RSS <image><url> and Atom <icon> point at the site icon even when the
        # watched address is a feed path on another host.
        feed_image = re.search(r'<image>\s*<url>\s*(https?://[^<\s]+)', head, re.I)
        atom_icon = re.search(r'<icon>\s*(https?://[^<\s]+)', head, re.I)
        if feed_image and try_icons([(64, False, feed_image.group(1).strip())], page_host):
            return
        if atom_icon and try_icons([(64, False, atom_icon.group(1).strip())], page_host):
            return

        candidates = icon_links(html, page_url)
        if not candidates:
            # Absolute /favicon.ico resolves against the origin, not the document path.
            candidates.append((16, False, urljoin(page_url, '/favicon.ico')))
        if try_icons(candidates, page_host):
            return

        # Plain files (CHANGELOG.txt) and feeds have no usable <link rel="icon">
        # on the document itself. Read icons from the site root, then /favicon.ico.
        homes = []
        site_link = re.search(r'<channel>[\s\S]{0,2000}?<link>\s*(https?://[^<\s]+)', head, re.I)
        if site_link:
            homes.append(site_link.group(1).strip())
        parsed = urlparse(page_url)
        if parsed.scheme in ('http', 'https') and parsed.netloc and parsed.path not in ('', '/'):
            homes.append(f'{parsed.scheme}://{parsed.netloc}/')

        seen_origins = set()
        for home in homes:
            home_parsed = urlparse(home)
            if home_parsed.scheme not in ('http', 'https') or not home_parsed.netloc:
                continue
            origin = f'{home_parsed.scheme}://{home_parsed.netloc}'
            if origin in seen_origins:
                continue
            seen_origins.add(origin)
            homepage = home if home_parsed.path else origin + '/'
            ok, _reason = is_fetch_url_allowed(homepage)
            if not ok:
                continue

            headers = {}
            if home_parsed.netloc == page_host and isinstance(request_headers, dict):
                headers = dict(request_headers)
            elif isinstance(request_headers, dict) and request_headers.get('User-Agent'):
                headers = {'User-Agent': request_headers['User-Agent']}

            homepage_html = ''
            final_url = homepage
            try:
                response = self._get_with_redirect_checks(
                    session, homepage, headers, proxies, budget, allow_iana_restricted
                )
                if response is not None and response.status_code == 200 and response.content:
                    ctype = (response.headers.get('content-type') or '').lower()
                    if 'html' in ctype or 'xml' in ctype:
                        homepage_html = response.content[:200000].decode('utf-8', errors='replace')
                        final_url = getattr(response, 'url', None) or homepage
            except Exception as e:
                logger.debug(f"Favicon homepage lookup failed {homepage}: {e}")

            if homepage_html and try_icons(icon_links(homepage_html, final_url), home_parsed.netloc):
                return
            if try_icons([(16, False, origin + '/favicon.ico')], home_parsed.netloc):
                return

    @staticmethod
    def _favicon_from_data_uri(uri):
        import base64
        import re

        match = re.match(r'^data:([^;,]+)?(;base64)?,(.*)$', uri, re.DOTALL)
        if not match:
            return None
        mime = (match.group(1) or 'image/x-icon').lower()
        payload = match.group(3) or ''
        if match.group(2):
            try:
                raw = base64.b64decode(payload, validate=True)
                encoded = payload.strip()
            except Exception:
                return None
        else:
            from urllib.parse import unquote_to_bytes
            raw = unquote_to_bytes(payload)
            encoded = base64.b64encode(raw).decode('ascii')
        if not raw or len(raw) > 1024 * 1024:
            return None
        return {'url': uri[:80], 'base64': encoded, 'mime_type': mime}

    def _get_with_redirect_checks(self, session, url, headers, proxies, timeout, allow_iana_restricted):
        current = url
        response = None
        for _ in range(4):
            response = session.get(
                current,
                headers=headers,
                timeout=timeout,
                proxies=proxies,
                verify=False,
                allow_redirects=False,
            )
            if not response.is_redirect:
                return response
            location = response.headers.get('Location', '')
            redirect_url = urljoin(current, location)
            if not allow_iana_restricted and is_url_private_or_parser_confused(redirect_url):
                raise Exception(f"Favicon redirect blocked: {redirect_url}")
            ok, reason = is_fetch_url_allowed(redirect_url)
            if not ok:
                raise Exception(reason)
            current = redirect_url
        raise Exception('Too many favicon redirects')

    async def run(self,
                  fetch_favicon=True,
                  current_include_filters=None,
                  empty_pages_are_a_change=False,
                  ignore_status_codes=False,
                  is_binary=False,
                  request_body=None,
                  request_headers=None,
                  request_method=None,
                  screenshot_format=None,
                  timeout=None,
                  url=None,
                  watch_uuid=None,
                  ):
        """Async wrapper that runs the synchronous requests code in a thread pool"""

        loop = asyncio.get_event_loop()

        # Run the synchronous _run_sync in a thread pool to avoid blocking the event loop
        # Retry logic is handled by requests' HTTPAdapter (see _run_sync for configuration)
        await loop.run_in_executor(
            None,  # Use default ThreadPoolExecutor
            lambda: self._run_sync(
                url=url,
                timeout=timeout,
                request_headers=request_headers,
                request_body=request_body,
                request_method=request_method,
                ignore_status_codes=ignore_status_codes,
                current_include_filters=current_include_filters,
                is_binary=is_binary,
                empty_pages_are_a_change=empty_pages_are_a_change,
                watch_uuid=watch_uuid,
                fetch_favicon=fetch_favicon,
            )
        )

    async def quit(self, watch=None):
        # In case they switched to `requests` fetcher from something else
        # Then the screenshot could be old, in any case, it's not used here.
        # REMOVE_REQUESTS_OLD_SCREENSHOTS - Mainly used for testing
        if strtobool(os.getenv("REMOVE_REQUESTS_OLD_SCREENSHOTS", 'true')):
            screenshot = watch.get_screenshot()
            if screenshot:
                try:
                    os.unlink(screenshot)
                except Exception as e:
                    logger.warning(f"Failed to unlink screenshot: {screenshot} - {e}")


# Plugin registration for built-in fetcher
class RequestsFetcherPlugin:
    """Plugin class that registers the requests fetcher as a built-in plugin."""

    def register_content_fetcher(self):
        """Register the requests fetcher"""
        return ('html_requests', fetcher)


# Create module-level instance for plugin registration
requests_plugin = RequestsFetcherPlugin()
