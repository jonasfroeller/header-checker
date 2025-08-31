import logging
import os
import socket
import time
import requests
from typing import Dict, Any, List, Optional, Tuple
import ipaddress
from urllib.parse import urlparse
import subprocess
import tempfile
import json
from pathlib import Path
import sys
import re

logger = logging.getLogger(__name__)


class HumbleService:
    """Service for HTTP security header analysis"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def check_availability(self) -> bool:
        """Check if humble CLI is available and minimally runnable.

        1) Verify HUMBLE_PY or HUMBLE_HOME env points to an existing humble.py
        2) Verify a Python launcher is available (py/python3/python)
        3) Attempt a quick "--version" call with short timeout
        """
        humble_py = self._resolve_humble_py()
        if not humble_py:
            logger.debug("HUMBLE_PY/HUMBLE_HOME not configured or humble.py not found")
            return False

        python_exe = self._resolve_python_launcher()
        if not python_exe:
            logger.debug("No suitable Python launcher found for humble (py/python3/python)")
            return False

        try:
            proc = subprocess.run(
                [python_exe, str(humble_py), "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=min(self.timeout, 3)
            )
            return proc.returncode == 0 or proc.returncode == 2  # help/version may return 0/2
        except Exception as e:
            logger.debug(f"Humble version check failed: {e}")
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
                try:
                    humble_ok, humble_result = self._analyze_with_humble(
                        url=url,
                        headers=response['headers']
                    )
                except Exception as _e:
                    logger.warning(f"Humble analysis failed unexpectedly: {_e}")
                    humble_ok, humble_result = False, None

                if humble_ok and humble_result:
                    analysis_data = self._map_humble_to_internal(
                        url=url,
                        status_code=response['status_code'],
                        headers=response['headers'],
                        scan_time=scan_time,
                        humble_data=humble_result
                    )
                    try:
                        logger.debug("Humble analysis path used")
                    except Exception:
                        pass
                    return {
                        'success': True,
                        'data': analysis_data
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Humble analysis failed'
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
            # Prepare session: no proxies, UA set
            session = requests.Session()
            session.trust_env = False
            session.headers.update({
                'User-Agent': 'SecurityHeaderAnalyzer/1.0 (HTTP Security Header Checker)'
            })

            # Validate initial target
            parsed = urlparse(url)
            if not self._is_allowed_port(parsed):
                return {'success': False, 'error': 'Disallowed port'}
            if not self._hostname_is_public(parsed.hostname):
                return {'success': False, 'error': 'Target host is not public'}

            # First try HEAD without redirects; then handle up to 3 redirects manually with validation
            max_redirects = 3
            current_url = url
            for _ in range(max_redirects + 1):
                resp = session.head(current_url, timeout=self.timeout, allow_redirects=False)
                # If redirect, validate the Location and continue
                if resp.is_redirect or resp.is_permanent_redirect:
                    location = resp.headers.get('Location')
                    if not location:
                        return {'success': False, 'error': 'Redirect without Location header'}
                    next_url = requests.compat.urljoin(current_url, location)
                    parsed_next = urlparse(next_url)
                    if parsed_next.scheme not in ('http', 'https'):
                        return {'success': False, 'error': 'Disallowed redirect scheme'}
                    if not self._is_allowed_port(parsed_next):
                        return {'success': False, 'error': 'Disallowed redirect port'}
                    if not self._hostname_is_public(parsed_next.hostname):
                        return {'success': False, 'error': 'Redirect target is not public'}
                    current_url = next_url
                    continue

                # Non-redirect response: OK, we have headers
                headers = dict(resp.headers)
                status_code = resp.status_code

                # Some servers may not support HEAD; fallback to safe GET
                if status_code >= 400:
                    try:
                        get_resp = session.get(current_url, timeout=self.timeout, allow_redirects=False, stream=True)
                        headers = dict(get_resp.headers)
                        status_code = get_resp.status_code
                        # Do not download body
                        get_resp.close()
                    except requests.RequestException:
                        pass

                return {
                    'success': True,
                    'headers': headers,
                    'status_code': status_code,
                    'final_url': current_url
                }

            return {'success': False, 'error': 'Too many redirects'}

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

    # ---------------- Humble CLI Integration ----------------

    def _resolve_humble_py(self) -> Optional[Path]:
        """Resolve path to humble.py using env vars.

        HUMBLE_PY: full path to humble.py
        HUMBLE_HOME: directory containing humble.py
        """
        env_file = os.environ.get('HUMBLE_PY')
        if env_file:
            p = Path(env_file).expanduser()
            if p.is_file():
                return p

        env_home = os.environ.get('HUMBLE_HOME')
        if env_home:
            p = Path(env_home).expanduser() / 'humble.py'
            if p.is_file():
                return p

        try:
            repo_root = Path(__file__).resolve().parents[1]
            candidates = [
                repo_root / 'vendor' / 'humble' / 'humble.py',
                repo_root / '.tools' / 'humble' / 'humble.py'
            ]
            for c in candidates:
                if c.is_file():
                    return c
        except Exception:
            pass

        return None

    def _resolve_python_launcher(self) -> Optional[str]:
        """Pick a Python launcher likely to exist in the environment."""
        override = os.environ.get('PYTHON_LAUNCHER')
        if override:
            return override
        try:
            if sys.executable:
                return sys.executable
        except Exception:
            pass
        if os.name == 'nt':
            return 'py'
        return 'python3'

    def _analyze_with_humble(self, url: str, headers: Dict[str, str]) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Run humble analysis prioritizing JSON outputs (brief and CICD).

        Returns (ok, result_dict)
        """
        humble_py = self._resolve_humble_py()
        if not humble_py:
            logger.info("Humble CLI not configured; skipping humble analysis")
            return False, None

        python_exe = self._resolve_python_launcher()
        if not python_exe:
            logger.info("Python launcher not found; skipping humble analysis")
            return False, None

        # Brief JSON export (-o json -b) for structured lists
        try:
            with tempfile.TemporaryDirectory() as tmpdir_json:
                tmp_json_path = Path(tmpdir_json)
                output_json = tmp_json_path / 'humble_output.json'
                cmd_json = [
                    python_exe,
                    str(humble_py),
                    '-u', url,
                    '-b',
                    '-o', 'json',
                    '-op', str(tmp_json_path),
                    '-of', output_json.stem
                ]
                try:
                    proc_json = subprocess.run(
                        cmd_json,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=min(self.timeout, 10),
                        cwd=str(humble_py.parent)
                    )
                except subprocess.TimeoutExpired:
                    proc_json = None
                except Exception:
                    proc_json = None

                produced_json: Optional[Path] = None
                if output_json.exists():
                    produced_json = output_json
                else:
                    try:
                        for p in tmp_json_path.glob('*.json'):
                            produced_json = p
                            break
                    except Exception:
                        produced_json = None

                if produced_json and produced_json.exists():
                    try:
                        jtext = produced_json.read_text(encoding='utf-8', errors='ignore')
                        parsed_json = self._parse_humble_json_brief(jtext)
                        if parsed_json:
                            return True, parsed_json
                    except Exception:
                        pass
        except Exception:
            pass
        cicd_ok, cicd_data = self._try_humble_cicd_json(
            python_exe, humble_py, input_file=None, tmp_path=None, url=url
        )
        if cicd_ok:
            return True, self._scrub_sensitive_keys(cicd_data)
        return False, None

    def _parse_humble_json_brief(self, json_text: str) -> Optional[Dict[str, Any]]:
        """Parse Humble's brief JSON export (-o json -b) into a generic dict.

        Extracts present headers, missing headers, deprecated/insecure items, fingerprint headers,
        empty value headers, grade, totals, info and browser compatibility references.
        """
        try:
            data = json.loads(json_text)
        except Exception:
            return None

        out: Dict[str, Any] = {
            'present_headers': [],
            'missing_headers': [],
            'deprecated_or_insecure': [],
            'fingerprint_headers': [],
            'empty_values': [],
            'grade': None,
            'totals': {},
            'info': {},
            'browser_compat': [],
            'browser_compat_map': [],
            'analysis_results_lines': [],
            'analysis_runtime_seconds': None,
            'footnote_experimental_meaning': None,
            'footnote_ref': None,
            'raw_object': data,
            'source': 'json_brief'
        }

        def clean(name: str) -> str:
            s = (name or '').strip()
            if s.startswith('(*)'):
                s = s[3:].strip()
            return s

        enabled = data.get('[1. Enabled HTTP Security Headers]') or []
        if isinstance(enabled, list):
            for name in enabled:
                if isinstance(name, str) and name:
                    out['present_headers'].append({'name': clean(name), 'value': ''})

        missing = data.get('[2. Missing HTTP Security Headers]') or []
        if isinstance(missing, list):
            for name in missing:
                if isinstance(name, str) and name:
                    out['missing_headers'].append(clean(name))

        dep = data.get('[4. Deprecated HTTP Response Headers/Protocols and Insecure Values]') or []
        if isinstance(dep, list):
            for entry in dep:
                if isinstance(entry, str) and entry:
                    header_name = clean(entry.split(':', 1)[0])
                    out['deprecated_or_insecure'].append({'header': header_name or 'General', 'message': entry})

        fp = data.get('[3. Fingerprint HTTP Response Headers]') or []
        if isinstance(fp, list):
            for entry in fp:
                if isinstance(entry, str) and entry:
                    out['fingerprint_headers'].append(entry)

        empty_vals = data.get('[5. Empty HTTP Response Headers Values]') or []
        if isinstance(empty_vals, list):
            for entry in empty_vals:
                if isinstance(entry, str) and entry and not entry.lower().startswith('nothing to report'):
                    out['empty_values'].append(entry)

        info = data.get('[0. Info]')
        if isinstance(info, dict):
            out['info'] = info

        bc = data.get('[6. Browser Compatibility for Enabled HTTP Security Headers]') or []
        if isinstance(bc, list):
            bc_list = [s for s in bc if isinstance(s, str)]
            out['browser_compat'] = bc_list
            for s in bc_list:
                try:
                    parts = s.split(':', 1)
                    if len(parts) == 2:
                        header = parts[0].strip()
                        url = parts[1].strip()
                        out['browser_compat_map'].append({'header': header, 'url': url})
                except Exception:
                    continue

        results = data.get('[7. Analysis Results]') or []
        if isinstance(results, list):
            out['analysis_results_lines'] = [s for s in results if isinstance(s, str)]
            for line in out['analysis_results_lines']:
                m = re.search(r'Analysis\s+Grade\s*:\s*([A-F])', line)
                if m:
                    out['grade'] = m.group(1)
                m2 = re.search(r'(Enabled headers|Missing headers|Fingerprint headers|Deprecated/Insecure headers|Empty headers|Findings to review):\s*([0-9]+)', line)
                if m2:
                    key = m2.group(1).lower().replace(' ', '_').replace('/', '_')
                    try:
                        out['totals'][key] = int(m2.group(2))
                    except Exception:
                        out['totals'][key] = m2.group(2)
                m3 = re.search(r'Done in\s*([0-9]+(?:\.[0-9]+)?)\s*seconds', line)
                if m3 and out['analysis_runtime_seconds'] is None:
                    try:
                        out['analysis_runtime_seconds'] = float(m3.group(1))
                    except Exception:
                        pass
                if "'(*)' meaning:" in line:
                    try:
                        out['footnote_experimental_meaning'] = line.split(':', 1)[1].strip()
                    except Exception:
                        out['footnote_experimental_meaning'] = line
                if "'(*)' ref:" in line:
                    try:
                        out['footnote_ref'] = line.split(':', 1)[1].strip()
                    except Exception:
                        out['footnote_ref'] = line

        # Ensure totals have counts even if not present in [7.] section
        if 'enabled_headers' not in out['totals'] and out['present_headers']:
            out['totals']['enabled_headers'] = len(out['present_headers'])
        if 'missing_headers' not in out['totals'] and out['missing_headers']:
            out['totals']['missing_headers'] = len(out['missing_headers'])
        if 'fingerprint_headers' not in out['totals'] and out['fingerprint_headers']:
            out['totals']['fingerprint_headers'] = len(out['fingerprint_headers'])

        return self._scrub_sensitive_keys(out)

    def _try_humble_cicd_json(self, python_exe: str, humble_py: Path, input_file: Optional[Path], tmp_path: Optional[Path], url: Optional[str] = None) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Attempt to run humble with -cicd to get JSON summary if XML path fails."""
        try:
            cmd = [python_exe, str(humble_py)]
            if url:
                cmd += ['-u', url, '-cicd']
            elif input_file is not None:
                cmd += ['-if', str(input_file), '-cicd']
            else:
                return False, None
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=min(self.timeout, 10),
                cwd=str(humble_py.parent)
            )
            if proc.returncode == 0 and proc.stdout:
                data = json.loads(proc.stdout)
                return True, self._scrub_sensitive_keys({ 'cicd': data, 'source': 'cicd' })
            return False, None
        except Exception as e:
            logger.debug(f"Humble CICD JSON failed: {e}")
            return False, None

    def _map_humble_to_internal(self, url: str, status_code: int, headers: Dict[str, str], scan_time: float, humble_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map parsed humble data into the application's response schema."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        # Normalize raw headers for lookups
        normalized_raw_headers = {k.lower(): v for k, v in headers.items()}

        # Grade & score: use humble grade only
        percentage = None
        derived_grade = None
        humble_grade = None

        # Accept humble CICD grade if provided
        cicd = humble_data.get('cicd') if isinstance(humble_data, dict) else None
        if cicd and isinstance(cicd, dict):
            try:
                ag = cicd.get('Analysis Grade') or {}
                g = ag.get('Grade')
                if isinstance(g, str) and g:
                    humble_grade = (g[:1] or '').strip().upper()
            except Exception:
                pass
        if not humble_grade and isinstance(humble_data.get('grade'), str):
            g2 = humble_data.get('grade')
            if g2:
                humble_grade = (g2[:1] or '').strip().upper()

        grade = (humble_grade or derived_grade) or 'F'
        if humble_grade:
            percentage = self._grade_to_score(humble_grade)

        # Build UI-expected structures from humble output
        present_list: List[Dict[str, str]] = []
        missing_list: List[str] = []
        warnings_list: List[Dict[str, str]] = []

        try:
            if isinstance(humble_data, dict):
                present_list = list(humble_data.get('present_headers') or [])
                missing_list = list(humble_data.get('missing_headers') or [])
                di_list = list(humble_data.get('deprecated_or_insecure') or [])
                for item in di_list:
                    if not isinstance(item, dict):
                        continue
                    hdr = str(item.get('header') or 'General')
                    msg = str(item.get('message') or '').strip()
                    if hdr or msg:
                        warnings_list.append({'header': hdr, 'message': msg})

                # Fill empty values for present headers from raw headers and deduplicate by name (case-insensitive)
                dedup: Dict[str, Dict[str, str]] = {}
                for ph in present_list:
                    if not isinstance(ph, dict):
                        continue
                    name = str((ph.get('name') or ph.get('header') or '')).strip()
                    if not name:
                        continue
                    key = name.lower()
                    val: str = '' if ph.get('value') is None else str(ph.get('value'))
                    if not val:
                        try:
                            raw_val = normalized_raw_headers.get(key)
                            if raw_val is not None:
                                val = str(raw_val)
                        except Exception:
                            pass
                    if key not in dedup:
                        dedup[key] = {'name': name, 'value': val}
                    else:
                        # Prefer non-empty value if duplicate appears later
                        if not dedup[key]['value'] and val:
                            dedup[key]['value'] = val

                if dedup:
                    present_list = [{'name': v['name'], 'value': v['value']} for v in dedup.values()]
                    try:
                        # Also update humble_data copy for transparency in API output
                        humble_data['present_headers'] = [dict(x) for x in present_list]
                    except Exception:
                        pass
        except Exception:
            present_list, missing_list, warnings_list = [], [], []

        # CICD summary, synthesize present headers from raw headers
        if not present_list and isinstance(headers, dict):
            try:
                for name, value in headers.items():
                    if not name:
                        continue
                    present_list.append({'name': str(name), 'value': '' if value is None else str(value)})
            except Exception:
                pass

        # security_headers object keyed by header name for the UI
        security_headers: Dict[str, Dict[str, Any]] = {}
        seen_keys: set = set()
        for item in present_list:
            try:
                name = str(item.get('name') or '').strip()
                if not name:
                    name = str(item.get('header') or '').strip()
                if not name:
                    continue
                key = name.lower()
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                val = '' if item.get('value') is None else str(item.get('value'))
                if not val:
                    try:
                        raw_val = normalized_raw_headers.get(key)
                        if raw_val is not None:
                            val = str(raw_val)
                    except Exception:
                        pass
                security_headers[name] = {
                    'present': True,
                    'value': val,
                    'status': 'present'
                }
            except Exception:
                continue

        payload: Dict[str, Any] = {
            'timestamp': timestamp,
            'scan_time': scan_time,
            'url': url,
            'status_code': status_code,
            'headers': headers,
            'grade': grade,
            'analysis_source': 'humble',
            'humble': self._scrub_sensitive_keys(humble_data),
            'security_headers': security_headers,
            'missing_headers': missing_list,
            'warnings': warnings_list
        }
        if percentage is not None:
            payload['score'] = round(float(percentage), 1)
        return payload

    def _scrub_sensitive_keys(self, obj: Any) -> Any:
        """Recursively remove sensitive keys (e.g., 'File') from nested dicts/lists.

        This prevents leaking local filesystem paths in prod responses.
        """
        try:
            if isinstance(obj, dict):
                sanitized: Dict[str, Any] = {}
                for k, v in obj.items():
                    if isinstance(k, str) and k.strip().lower() == 'file':
                        continue
                    sanitized[k] = self._scrub_sensitive_keys(v)
                return sanitized
            if isinstance(obj, list):
                return [self._scrub_sensitive_keys(x) for x in obj]
            return obj
        except Exception:
            return obj

    def _grade_to_score(self, grade: str) -> float:
        g = (grade or '').strip().upper()
        return {
            'A': 95.0,
            'B': 85.0,
            'C': 75.0,
            'D': 65.0,
            'F': 50.0,
        }.get(g, 50.0)

    # ---- SSRF helpers ----
    def _hostname_is_public(self, hostname: str) -> bool:
        """Resolve hostname and ensure all resolved IPs are public (IPv4/IPv6)."""
        if not hostname:
            return False
        try:
            infos = socket.getaddrinfo(hostname, None)
        except Exception:
            return False
        for _, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast:
                    return False
            except ValueError:
                return False
        return True

    def _is_allowed_port(self, parsed) -> bool:
        """Only allow default ports 80/443 or explicit 80/443."""
        try:
            port = parsed.port
        except ValueError:
            return False
        if port is None:
            return parsed.scheme in ('http', 'https')
        return port in (80, 443)
