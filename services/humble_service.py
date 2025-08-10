import logging
import os
import socket
import time
import requests
from typing import Dict, Any

logger = logging.getLogger(__name__)


class HumbleService:
    """Service for HTTP security header analysis"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.security_headers = {
            'Content-Security-Policy': {
                'description': 'Protects against XSS and data injection attacks',
                'weight': 25
            },
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'weight': 20
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'weight': 15
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'weight': 10
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'weight': 10
            },
            'Permissions-Policy': {
                'description': 'Controls browser features and APIs',
                'weight': 10
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS protection (deprecated but still useful)',
                'weight': 5
            },
            'Cross-Origin-Embedder-Policy': {
                'description': 'Controls cross-origin resource embedding',
                'weight': 5
            }
        }

    def check_availability(self) -> bool:
        """Check if service is available using DNS + multiple lightweight probes.

        Strategy:
        1) Optional env override via HUMBLE_HEALTHCHECK_URL
        2) DNS resolution check (fast failure if no outbound DNS)
        3) Try multiple HEAD probes with short timeouts; succeed on first <400
        """
        timeout = min(self.timeout, 3)

        # Build probe list (env-first, then common lightweight endpoints)
        probe_urls = []
        env_url = os.environ.get("HUMBLE_HEALTHCHECK_URL")
        if env_url:
            probe_urls.append(env_url.strip())
        probe_urls.extend([
            "https://www.google.com/generate_204",
            "https://httpbin.org/status/204",
            "https://example.com",
        ])

        # Quick DNS check on first hostname to avoid long HTTP timeouts when DNS is blocked
        try:
            first_host = requests.utils.urlparse(probe_urls[0]).hostname or "example.com"
            socket.gethostbyname(first_host)
        except Exception as e:
            logger.warning(f"Availability DNS resolution failed for {first_host}: {e}")
            return False

        session = requests.Session()
        session.headers.update({
            'User-Agent': 'SecurityHeaderAnalyzer/1.0 (HTTP Security Header Checker)'
        })

        for url in probe_urls:
            try:
                logger.debug(f"Availability probe via HEAD {url} (timeout={timeout}s)")
                resp = session.head(url, timeout=timeout, allow_redirects=True)
                if resp.status_code < 400:
                    return True
                logger.debug(f"Probe {url} returned status {resp.status_code}")
            except requests.RequestException as e:
                logger.debug(f"Probe {url} failed: {e}")
                continue

        logger.warning("All availability probes failed; marking humble as unavailable")
        return False

    def analyze(self, url: str, try_fallback: bool = False) -> Dict[str, Any]:
        """
        Analyze a URL for HTTP security headers with automatic protocol fallback

        Args:
            url: The URL to analyze
            try_fallback: Whether to try HTTP fallback if HTTPS fails

        Returns:
            Dict containing success status and either data or error
        """
        try:
            start_time = time.time()

            logger.debug(f"Analyzing URL: {url}")
            response = self._fetch_headers(url)

            if not response['success'] and try_fallback and url.startswith('https://'):
                logger.debug(f"HTTPS failed, trying HTTP fallback for: {url}")
                http_url = url.replace('https://', 'http://', 1)
                response = self._fetch_headers(http_url)
                if response['success']:
                    url = http_url

            scan_time = round(time.time() - start_time, 2)

            if response['success']:
                analysis_data = self._analyze_headers(
                    url,
                    response['headers'],
                    response['status_code'],
                    scan_time
                )
                return {
                    'success': True,
                    'data': analysis_data
                }
            else:
                return {
                    'success': False,
                    'error': response['error']
                }

        except Exception as e:
            logger.error(f"Unexpected error during analysis: {e}")
            return {
                'success': False,
                'error': f"Unexpected error: {str(e)}"
            }

    def _fetch_headers(self, url: str) -> Dict[str, Any]:
        """Fetch HTTP headers from the given URL"""
        try:
            # Configure session with timeout and user agent
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'SecurityHeaderAnalyzer/1.0 (HTTP Security Header Checker)'
            })

            # Make HEAD request first (faster), fallback to GET if needed
            try:
                response = session.head(
                    url, timeout=self.timeout, allow_redirects=True)
                headers = dict(response.headers)
                status_code = response.status_code
            except requests.RequestException:
                # Fallback to GET request
                response = session.get(
                    url, timeout=self.timeout, allow_redirects=True)
                headers = dict(response.headers)
                status_code = response.status_code

            return {
                'success': True,
                'headers': headers,
                'status_code': status_code,
                'final_url': response.url
            }

        except requests.exceptions.Timeout:
            return {
                'success': False,
                'error': f'Request timed out after {self.timeout} seconds'
            }
        except requests.exceptions.ConnectionError:
            return {
                'success': False,
                'error': 'Failed to connect to the URL'
            }
        except requests.exceptions.InvalidURL:
            return {
                'success': False,
                'error': 'Invalid URL format'
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Request failed: {str(e)}'
            }

    def _analyze_headers(self, url: str, headers: Dict[str, str], status_code: int, scan_time: float) -> Dict[str, Any]:
        """Analyze security headers and generate report"""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        # Normalize header names (case-insensitive)
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        security_headers = {}
        missing_headers = []
        warnings = []
        total_score = 0
        max_score = sum(header['weight']
                        for header in self.security_headers.values())

        # Analyze each security header
        for header_name, header_info in self.security_headers.items():
            header_key = header_name.lower()

            if header_key in normalized_headers:
                header_value = normalized_headers[header_key]
                analysis = self._analyze_specific_header(
                    header_name, header_value)

                security_headers[header_name] = {
                    'present': True,
                    'value': header_value,
                    'status': analysis['status'],
                    'recommendation': analysis.get('recommendation'),
                    'description': header_info['description']
                }

                # Add score based on status
                if analysis['status'] == 'good':
                    total_score += header_info['weight']
                elif analysis['status'] == 'warning':
                    total_score += header_info['weight'] * 0.5
                # No score for 'error' status

                # Add warning message if present
                if analysis.get('warning'):
                    warnings.append({
                        'header': header_name,
                        'message': analysis['warning']
                    })
            else:
                missing_headers.append(header_name)
                security_headers[header_name] = {
                    'present': False,
                    'value': None,
                    'status': 'missing',
                    'recommendation': f'Add {header_name} header to improve security',
                    'description': header_info['description']
                }

        # Calculate grade
        percentage = (total_score / max_score) * 100 if max_score > 0 else 0
        grade = self._calculate_grade(percentage)

        return {
            'timestamp': timestamp,
            'scan_time': scan_time,
            'url': url,
            'status_code': status_code,
            'headers': headers,
            'security_headers': security_headers,
            'missing_headers': missing_headers,
            'warnings': warnings,
            'score': round(percentage, 1),
            'grade': grade,
            'total_headers_found': len([h for h in security_headers.values() if h['present']]),
            'total_headers_checked': len(self.security_headers)
        }

    def _analyze_specific_header(self, header_name: str, value: str) -> Dict[str, Any]:
        """Analyze a specific security header value"""

        if header_name == 'Content-Security-Policy':
            if 'unsafe-inline' in value or 'unsafe-eval' in value:
                return {
                    'status': 'warning',
                    'warning': 'CSP contains unsafe directives (unsafe-inline or unsafe-eval)',
                    'recommendation': 'Remove unsafe directives and use nonces or hashes instead'
                }
            elif len(value.split(';')) >= 3:
                return {
                    'status': 'good',
                    'recommendation': 'Good CSP configuration with multiple directives'
                }
            else:
                return {
                    'status': 'warning',
                    'warning': 'CSP is present but may be too permissive',
                    'recommendation': 'Consider adding more restrictive directives'
                }

        elif header_name == 'Strict-Transport-Security':
            if 'max-age=' not in value:
                return {
                    'status': 'error',
                    'warning': 'HSTS header missing max-age directive',
                    'recommendation': 'Add max-age directive with appropriate value'
                }
            elif 'includeSubDomains' in value:
                return {
                    'status': 'good',
                    'recommendation': 'Excellent HSTS configuration with subdomain protection'
                }
            else:
                return {
                    'status': 'warning',
                    'warning': 'HSTS does not include subdomains',
                    'recommendation': 'Consider adding includeSubDomains directive'
                }

        elif header_name == 'X-Frame-Options':
            if value.upper() in ['DENY', 'SAMEORIGIN']:
                return {
                    'status': 'good',
                    'recommendation': 'Good clickjacking protection'
                }
            elif value.upper().startswith('ALLOW-FROM'):
                return {
                    'status': 'warning',
                    'warning': 'ALLOW-FROM is deprecated',
                    'recommendation': 'Use CSP frame-ancestors directive instead'
                }
            else:
                return {
                    'status': 'error',
                    'warning': 'Invalid X-Frame-Options value',
                    'recommendation': 'Use DENY or SAMEORIGIN'
                }

        elif header_name == 'X-Content-Type-Options':
            if value.lower() == 'nosniff':
                return {
                    'status': 'good',
                    'recommendation': 'Good MIME type sniffing protection'
                }
            else:
                return {
                    'status': 'error',
                    'warning': 'Invalid X-Content-Type-Options value',
                    'recommendation': 'Use "nosniff" value'
                }

        elif header_name == 'Referrer-Policy':
            safe_policies = ['no-referrer', 'same-origin',
                             'strict-origin', 'strict-origin-when-cross-origin']
            if value.lower() in safe_policies:
                return {
                    'status': 'good',
                    'recommendation': 'Good referrer policy configuration'
                }
            else:
                return {
                    'status': 'warning',
                    'warning': 'Referrer policy could be more restrictive',
                    'recommendation': 'Consider using strict-origin-when-cross-origin or stricter'
                }

        elif header_name == 'X-XSS-Protection':
            if value == '1; mode=block':
                return {
                    'status': 'good',
                    'recommendation': 'Good XSS protection (though deprecated, still useful)'
                }
            elif value == '0':
                return {
                    'status': 'warning',
                    'warning': 'XSS protection is disabled',
                    'recommendation': 'Enable XSS protection or rely on CSP'
                }
            else:
                return {
                    'status': 'warning',
                    'warning': 'XSS protection configuration could be improved',
                    'recommendation': 'Use "1; mode=block" or disable if using CSP'
                }

        # Default analysis for other headers
        return {
            'status': 'good',
            'recommendation': f'{header_name} is present'
        }

    def _calculate_grade(self, percentage: float) -> str:
        """Calculate letter grade based on percentage score"""
        if percentage >= 90:
            return 'A'
        elif percentage >= 80:
            return 'B'
        elif percentage >= 70:
            return 'C'
        elif percentage >= 60:
            return 'D'
        else:
            return 'F'
