import requests
import urllib.parse
import socket
import ssl
import re
from datetime import datetime
from bs4 import BeautifulSoup
import json

class URLAnalyzer:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.vulnerabilities = {
            'sql_injection': ["' OR '1'='1", '" OR "1"="1', "' UNION SELECT NULL --"],
            'xss': ['<script>alert(1)</script>', '" onmouseover="alert(1)'],
            'path_traversal': ['../../etc/passwd', '..\\..\\windows\\win.ini']
        }

    def analyze_url(self, url):
        # Basic validation
        if not url:
            return {
                'success': False,
                'error': 'URL cannot be empty'
            }

        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            # Parse URL
            parsed_url = urllib.parse.urlparse(url)
            domain = parsed_url.netloc
            hostname = parsed_url.hostname

            if not hostname:
                return {
                    'success': False,
                    'error': 'Invalid URL format',
                    'data': {},
                    'issues': ['Invalid URL format']
                }

            # Initialize results
            results = {
                'url': url,
                'domain': domain,
                'scheme': parsed_url.scheme,
                'path': parsed_url.path or '/',
                'query': parsed_url.query,
                'timestamp': datetime.now().isoformat(),
                'security_info': {},
                'response_info': {}
            }

            # DNS lookup
            try:
                ip = socket.gethostbyname(hostname)
                results['security_info']['ip'] = ip
            except socket.gaierror:
                results['security_info']['ip'] = 'Could not resolve DNS'

            # Make HTTP request
            try:
                response = requests.get(
                    url,
                    headers=self.headers,
                    verify=False,
                    timeout=5,
                    allow_redirects=True
                )

                # Response info
                results['response_info'] = {
                    'status_code': response.status_code,
                    'content_type': response.headers.get('content-type', 'Unknown'),
                    'server': response.headers.get('server', 'Unknown'),
                    'response_time': response.elapsed.total_seconds(),
                    'final_url': response.url,
                    'redirected': response.history != []
                }

                # Security headers
                results['security_info'].update({
                    'https': url.startswith('https://'),
                    'hsts': 'strict-transport-security' in response.headers,
                    'xss_protection': 'x-xss-protection' in response.headers,
                    'content_security': 'content-security-policy' in response.headers,
                    'frame_options': 'x-frame-options' in response.headers
                })

                # Content analysis
                if 'text/html' in response.headers.get('content-type', '').lower():
                    try:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        results['content_info'] = {
                            'title': soup.title.string.strip() if soup.title else 'No title',
                            'meta_description': soup.find('meta', {'name': 'description'}).get('content') if soup.find('meta', {'name': 'description'}) else 'No description',
                            'links_count': len(soup.find_all('a')),
                            'images_count': len(soup.find_all('img')),
                            'scripts_count': len(soup.find_all('script'))
                        }
                    except Exception as e:
                        results['content_info'] = {
                            'error': f'Could not parse HTML content: {str(e)}'
                        }

                return {
                    'success': True,
                    'data': results,
                    'issues': []
                }

            except requests.exceptions.RequestException as e:
                return {
                    'success': False,
                    'error': f'Request failed: {str(e)}',
                    'data': {},
                    'issues': [f'Request failed: {str(e)}']
                }

        except Exception as e:
            return {
                'success': False,
                'error': f'Analysis failed: {str(e)}',
                'data': {},
                'issues': [f'Analysis failed: {str(e)}']
            }



    def _analyze_ssl(self, hostname):
        """Analyze SSL/TLS configuration"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'has_ssl': True,
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'cert_expires': cert['notAfter'],
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'security_issues': []
                    }
        except Exception as e:
            return {
                'has_ssl': False,
                'security_issues': [str(e)]
            }

    def _analyze_headers(self, headers):
        """Analyze HTTP response headers for security"""
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-XSS-Protection': 'Missing XSS protection header'
        }
        
        results = {
            'security_headers': {},
            'missing_headers': [],
            'server_info': headers.get('Server', 'Not disclosed')
        }
        
        for header, message in security_headers.items():
            if header in headers:
                results['security_headers'][header] = headers[header]
            else:
                results['missing_headers'].append(message)
        
        return results

    def _scan_vulnerabilities(self, url, response):
        """Scan for common vulnerabilities"""
        results = {
            'found_vulnerabilities': [],
            'risk_level': 'low',
            'injectable_parameters': []
        }
        
        # Check URL parameters
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)
        
        for param_name, param_value in params.items():
            # Test each parameter for vulnerabilities
            for vuln_type, patterns in self.vulnerabilities.items():
                for pattern in patterns:
                    test_url = self._create_test_url(url, param_name, pattern)
                    try:
                        test_response = requests.get(test_url, headers=self.headers, timeout=5)
                        if self._detect_vulnerability(test_response, pattern):
                            results['found_vulnerabilities'].append({
                                'type': vuln_type,
                                'parameter': param_name,
                                'evidence': pattern
                            })
                            results['injectable_parameters'].append(param_name)
                            results['risk_level'] = 'high'
                    except:
                        continue
        
        # Check for exposed sensitive files
        sensitive_files = ['/robots.txt', '/sitemap.xml', '/.git/config', '/.env']
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        for file in sensitive_files:
            try:
                r = requests.get(base_url + file, headers=self.headers, timeout=5)
                if r.status_code == 200:
                    results['found_vulnerabilities'].append({
                        'type': 'sensitive_file',
                        'file': file,
                        'evidence': 'File accessible'
                    })
            except:
                continue
        
        return results

    def _analyze_content(self, response):
        """Analyze page content for security issues"""
        results = {
            'forms': [],
            'external_resources': [],
            'javascript_analysis': [],
            'information_disclosure': []
        }
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Analyze forms
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get'),
                    'inputs': []
                }
                
                for input_field in form.find_all('input'):
                    input_info = {
                        'type': input_field.get('type', 'text'),
                        'name': input_field.get('name', ''),
                        'id': input_field.get('id', '')
                    }
                    form_info['inputs'].append(input_info)
                
                results['forms'].append(form_info)
            
            # Find external resources
            for tag in soup.find_all(['script', 'link', 'img']):
                src = tag.get('src') or tag.get('href')
                if src and ('http://' in src or 'https://' in src):
                    results['external_resources'].append(src)
            
            # Look for potential information disclosure
            patterns = {
                'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
                'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
                'api_key': r'api[_-]?key[_-]?([\'"])?[\w\-]+\1?',
                'aws_key': r'AKIA[0-9A-Z]{16}'
            }
            
            for pattern_name, pattern in patterns.items():
                matches = re.findall(pattern, response.text)
                if matches:
                    results['information_disclosure'].append({
                        'type': pattern_name,
                        'count': len(matches)
                    })
            
        except Exception as e:
            results['error'] = str(e)
        
        return results

    def _create_test_url(self, url, param_name, test_value):
        """Create a URL with a test parameter value"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        params[param_name] = [test_value]
        new_query = urllib.parse.urlencode(params, doseq=True)
        return urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    def _detect_vulnerability(self, response, pattern):
        """Detect if a response indicates a vulnerability"""
        # Check for error messages
        error_patterns = [
            'sql error', 'mysql error', 'postgresql error',
            'stack trace', 'undefined index', 'undefined variable',
            'warning:', 'error:', 'exception'
        ]
        
        response_text = response.text.lower()
        
        # Check if the test pattern is reflected in the response
        if pattern.lower() in response_text:
            return True
        
        # Check for error messages
        for error in error_patterns:
            if error in response_text:
                return True
        
        return False

    def _calculate_security_score(self, results):
        """Calculate overall security score"""
        score = 100
        
        # SSL/TLS issues
        if not results['ssl_info']['has_ssl']:
            score -= 30
        
        # Missing security headers
        score -= len(results['headers_analysis']['missing_headers']) * 5
        
        # Vulnerabilities found
        if results['vulnerability_scan']:
            score -= len(results['vulnerability_scan']['found_vulnerabilities']) * 15
        
        # Information disclosure
        if results['content_analysis'].get('information_disclosure'):
            score -= len(results['content_analysis']['information_disclosure']) * 10
        
        return max(0, score)  # Ensure score doesn't go below 0
