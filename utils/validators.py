import re
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any


class URLValidator:
    """URL validation and sanitization utilities"""

    def __init__(self):
        self.url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            # domain...
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    def validate(self, url: str) -> Dict[str, Any]:
        """
        Validate and normalize a URL

        Returns:
            Dict with validation result and normalized URL
        """
        if not url:
            return {
                'valid': False,
                'message': 'URL cannot be empty'
            }

        if not isinstance(url, str):
            return {
                'valid': False,
                'message': 'URL must be a string'
            }

        if len(url) > 2048:
            return {
                'valid': False,
                'message': 'URL is too long (max 2048 characters)'
            }

        normalized_url = url.strip()
        if not normalized_url.startswith(('http://', 'https://')):
            normalized_url = 'https://' + normalized_url
        if not self.url_pattern.match(normalized_url):
            return {
                'valid': False,
                'message': 'Invalid URL format'
            }

        try:
            parsed = urlparse(normalized_url)

            if parsed.scheme not in ['http', 'https']:
                return {
                    'valid': False,
                    'message': 'URL must use http or https protocol'
                }

            if not parsed.netloc:
                return {
                    'valid': False,
                    'message': 'URL must have a valid hostname'
                }

            if parsed.hostname and self._is_private_ip(parsed.hostname):
                return {
                    'valid': False,
                    'message': 'Private IP addresses are not allowed'
                }

            if parsed.hostname and self._is_localhost(parsed.hostname):
                return {
                    'valid': False,
                    'message': 'Localhost addresses are not allowed'
                }

            clean_url = urlunparse(parsed)

            return {
                'valid': True,
                'normalized_url': clean_url,
                'try_fallback': parsed.scheme == 'https',
                'parsed': {
                    'scheme': parsed.scheme,
                    'hostname': parsed.hostname,
                    'port': parsed.port,
                    'path': parsed.path
                }
            }

        except Exception as e:
            return {
                'valid': False,
                'message': f'URL parsing error: {str(e)}'
            }

    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname is a private IP address"""
        if not hostname:
            return False

        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^::1$',
            r'^fc00:',
            r'^fe80:'
        ]

        for pattern in private_patterns:
            if re.match(pattern, hostname, re.IGNORECASE):
                return True

        return False

    def _is_localhost(self, hostname: str) -> bool:
        """Check if hostname is localhost"""
        if not hostname:
            return False

        localhost_names = ['localhost', '127.0.0.1', '::1']
        return hostname.lower() in localhost_names
