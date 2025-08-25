import ssl
import socket
import requests
import dns.resolver
import dns.zone
import dns.query
import whois
import json
import re
import logging
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, jsonify, request, render_template
from bs4 import BeautifulSoup
import subprocess
import time

# Configure logging
logging.basicConfig(level=logging.INFO)

def register_routes(app):
    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/api/domain-info', methods=['POST'])
    def get_domain_info():
        try:
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            
            # Remove protocol if present
            domain = domain.replace('http://', '').replace('https://', '')
            domain = domain.split('/')[0]  # Remove path if present
            
            # Get comprehensive domain analysis
            analysis = get_comprehensive_analysis(domain)
            
            return jsonify(analysis)
            
        except Exception as e:
            logging.error(f"Error in domain analysis: {str(e)}")
            return jsonify({'error': str(e)}), 500

    # Alternative endpoint for backward compatibility
    @app.route('/api/domain/analyze', methods=['POST'])
    def analyze_domain():
        try:
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            
            # Remove protocol if present
            domain = domain.replace('http://', '').replace('https://', '')
            domain = domain.split('/')[0]  # Remove path if present
            
            # Get comprehensive domain analysis
            analysis = get_comprehensive_analysis(domain)
            
            return jsonify(analysis)
            
        except Exception as e:
            logging.error(f"Error in domain analysis: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/certificate', methods=['POST'])
    def get_certificate():
        try:
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            
            cert_info = get_certificate_info(domain)
            return jsonify(cert_info)
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/subdomains', methods=['POST'])
    def get_subdomains():
        try:
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            
            subdomains = find_subdomains(domain)
            return jsonify({'subdomains': subdomains})
            
        except Exception as e:
            return jsonify({'error': str(e)}), 500

def get_comprehensive_analysis(domain):
    """Get comprehensive domain analysis including all features"""
    analysis = {
        'domain': domain,
        'timestamp': datetime.now().isoformat(),
        'certificate': {},
        'dns': {},
        'whois': {},
        'subdomains': [],
        'emails': [],
        'security': {},
        'server_info': {},
        'social_media': {},
        'technology': {},
        'performance': {}
    }
    
    # Use ThreadPoolExecutor for concurrent analysis
    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {
            executor.submit(get_certificate_info, domain): 'certificate',
            executor.submit(get_dns_info, domain): 'dns',
            executor.submit(get_whois_info, domain): 'whois',
            executor.submit(find_subdomains, domain): 'subdomains',
            executor.submit(extract_emails_comprehensive, domain): 'emails',
            executor.submit(get_security_headers, domain): 'security',
            executor.submit(get_server_info, domain): 'server_info',
            executor.submit(detect_technologies, domain): 'technology',
            executor.submit(get_performance_metrics, domain): 'performance'
        }
        
        for future in as_completed(futures):
            section = futures[future]
            try:
                result = future.result(timeout=30)
                analysis[section] = result
            except Exception as e:
                logging.error(f"Error in {section} analysis: {str(e)}")
                analysis[section] = {'error': str(e)}
    
    return analysis

def get_certificate_info(domain):
    """Enhanced certificate information with more details"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                cipher = secure_sock.cipher()
                
                # Parse certificate details
                cert_info = {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'serial_number': cert.get('serialNumber', ''),
                    'version': cert.get('version', ''),
                    'not_before': cert.get('notBefore', ''),
                    'not_after': cert.get('notAfter', ''),
                    'signature_algorithm': cert.get('signatureAlgorithm', ''),
                    'san': cert.get('subjectAltName', []),
                    'cipher_suite': {
                        'name': cipher[0] if cipher else '',
                        'version': cipher[1] if cipher else '',
                        'bits': cipher[2] if cipher else 0
                    }
                }
                
                # Calculate days until expiry
                if cert_info['not_after']:
                    try:
                        expiry_date = datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.now()).days
                        cert_info['days_until_expiry'] = days_until_expiry
                        cert_info['is_expired'] = days_until_expiry < 0
                        cert_info['expires_soon'] = 0 < days_until_expiry < 30
                    except:
                        pass
                
                return cert_info
                
    except Exception as e:
        return {'error': f'Could not retrieve certificate: {str(e)}'}

def get_dns_info(domain):
    """Comprehensive DNS information"""
    dns_info = {}
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'PTR']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_info[record_type] = []
            for rdata in answers:
                if record_type == 'MX':
                    dns_info[record_type].append({
                        'priority': rdata.preference,
                        'exchange': str(rdata.exchange)
                    })
                elif record_type == 'SOA':
                    dns_info[record_type].append({
                        'mname': str(rdata.mname),
                        'rname': str(rdata.rname),
                        'serial': rdata.serial,
                        'refresh': rdata.refresh,
                        'retry': rdata.retry,
                        'expire': rdata.expire,
                        'minimum': rdata.minimum
                    })
                else:
                    dns_info[record_type].append(str(rdata))
        except Exception as e:
            dns_info[record_type] = {'error': str(e)}
    
    # Try zone transfer (usually blocked)
    try:
        ns_servers = dns.resolver.resolve(domain, 'NS')
        for ns in ns_servers:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                dns_info['zone_transfer'] = 'Possible (Security Risk)'
                break
            except:
                continue
        if 'zone_transfer' not in dns_info:
            dns_info['zone_transfer'] = 'Blocked (Good)'
    except:
        dns_info['zone_transfer'] = 'Unknown'
    
    return dns_info

def get_whois_info(domain):
    """Get WHOIS information"""
    try:
        w = whois.whois(domain)
        
        # Clean up and format whois data
        whois_data = {}
        
        # Basic info
        fields_to_extract = [
            'domain_name', 'registrar', 'creation_date', 'expiration_date',
            'updated_date', 'status', 'name_servers', 'registrant_name',
            'registrant_email', 'admin_email', 'tech_email', 'country',
            'org', 'city', 'state'
        ]
        
        for field in fields_to_extract:
            value = getattr(w, field, None)
            if value:
                if isinstance(value, list) and len(value) > 0:
                    whois_data[field] = value[0] if len(value) == 1 else value
                elif isinstance(value, datetime):
                    whois_data[field] = value.isoformat()
                else:
                    whois_data[field] = str(value)
        
        return whois_data
        
    except Exception as e:
        return {'error': f'WHOIS lookup failed: {str(e)}'}

def find_subdomains(domain):
    """Comprehensive subdomain discovery"""
    subdomains = set()
    logging.info(f"Starting subdomain discovery for {domain}")
    
    # Certificate transparency logs search - This is the most effective method
    try:
        # First, try crt.sh API
        ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
        logging.info(f"Querying certificate transparency: {ct_url}")
        
        response = requests.get(ct_url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if response.status_code == 200:
            ct_data = response.json()
            logging.info(f"Found {len(ct_data)} certificate entries")
            
            for entry in ct_data:
                # Get both name_value and common_name fields
                names = []
                if entry.get('name_value'):
                    names.extend(entry['name_value'].split('\n'))
                if entry.get('common_name'):
                    names.append(entry['common_name'])
                
                for name in names:
                    name = name.strip().lower()
                    # Skip wildcards but process the rest
                    if name and not name.startswith('*') and name.endswith(domain):
                        # Clean up the subdomain
                        if name != domain:  # Don't include the main domain
                            subdomains.add(name)
            
            logging.info(f"Certificate transparency found {len(subdomains)} unique subdomains")
        else:
            logging.warning(f"Certificate transparency request failed: {response.status_code}")
            
    except Exception as e:
        logging.error(f"Certificate transparency search failed: {str(e)}")
    
    # Common subdomains to check via DNS
    common_subs = [
        'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test', 'staging',
        'shop', 'store', 'support', 'help', 'docs', 'cdn', 'static', 'img',
        'images', 'video', 'videos', 'music', 'download', 'downloads', 'files',
        'secure', 'ssl', 'vpn', 'remote', 'portal', 'login', 'auth', 'sso',
        'dashboard', 'panel', 'cpanel', 'whm', 'phpmyadmin', 'webmail',
        'mx', 'mx1', 'mx2', 'smtp', 'pop', 'imap', 'ns', 'ns1', 'ns2',
        'dns', 'cloud', 'app', 'apps', 'mobile', 'm', 'wap', 'forum',
        'forums', 'wiki', 'news', 'media', 'social', 'chat', 'live',
        'stream', 'radio', 'tv', 'video', 'game', 'games', 'demo',
        'beta', 'alpha', 'preview', 'sandbox', 'uat', 'qa', 'prod',
        'production', 'development', 'stage', 'demo', 'old', 'new',
        'backup', 'mirror', 'archive', 'cms', 'crm', 'erp', 'intranet'
    ]
    
    # Check common subdomains via DNS
    def check_subdomain(subdomain):
        try:
            full_domain = f"{subdomain}.{domain}"
            # Try both A and AAAA records
            try:
                dns.resolver.resolve(full_domain, 'A')
                return full_domain
            except:
                dns.resolver.resolve(full_domain, 'AAAA')
                return full_domain
        except:
            return None
    
    dns_found = 0
    with ThreadPoolExecutor(max_workers=20) as executor:  # Reduced workers to be nice to DNS servers
        futures = [executor.submit(check_subdomain, sub) for sub in common_subs]
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomains.add(result)
                dns_found += 1
    
    logging.info(f"DNS brute force found {dns_found} additional subdomains")
    
    # Try alternative certificate transparency sources
    try:
        # Try Censys (if we had API key, but we'll try the public interface)
        alternative_sources = [
            f"https://transparencyreport.google.com/transparencyreport/api/v3/httpsct?domain={domain}",
        ]
        
        # We can also try other CT log sources
        for url in alternative_sources:
            try:
                response = requests.get(url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                # This would require parsing different response formats
                # For now, we'll rely on crt.sh as the primary source
            except:
                continue
                
    except Exception as e:
        logging.debug(f"Alternative CT sources failed: {str(e)}")
    
    # Remove duplicates and sort
    final_subdomains = sorted(list(subdomains))
    logging.info(f"Total unique subdomains found: {len(final_subdomains)}")
    
    return final_subdomains

def extract_emails_comprehensive(domain):
    """Extract emails from multiple sources"""
    emails = set()
    
    # Extract from WHOIS
    try:
        whois_info = get_whois_info(domain)
        for key, value in whois_info.items():
            if 'email' in key and value:
                if isinstance(value, str) and '@' in value:
                    emails.add(value.lower())
    except:
        pass
    
    # Extract from website scraping
    try:
        urls_to_check = [
            f"https://{domain}",
            f"https://{domain}/contact",
            f"https://{domain}/about",
            f"https://{domain}/team",
            f"https://www.{domain}",
            f"https://www.{domain}/contact",
            f"https://www.{domain}/about"
        ]
        
        for url in urls_to_check:
            try:
                response = requests.get(url, timeout=10, headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                })
                
                if response.status_code == 200:
                    # Use regex to find email patterns
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    found_emails = re.findall(email_pattern, response.text)
                    for email in found_emails:
                        if domain in email.lower():  # Only include emails from the same domain
                            emails.add(email.lower())
                    
                    # Parse HTML for mailto links
                    soup = BeautifulSoup(response.text, 'html.parser')
                    mailto_links = soup.find_all('a', href=re.compile(r'^mailto:'))
                    for link in mailto_links:
                        href = link.get('href')
                        if href and href.startswith('mailto:'):
                            email = href.replace('mailto:', '').split('?')[0]
                            if '@' in email and domain in email.lower():
                                emails.add(email.lower())
                        
            except Exception as e:
                logging.debug(f"Error scraping {url}: {str(e)}")
                continue
                
    except Exception as e:
        logging.error(f"Error scraping website emails: {str(e)}")
    
    return list(emails)

def get_security_headers(domain):
    """Check security headers"""
    try:
        response = requests.get(f"https://{domain}", timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        headers = response.headers
        security_headers = {
            'strict_transport_security': headers.get('Strict-Transport-Security', 'Not Set'),
            'content_security_policy': headers.get('Content-Security-Policy', 'Not Set'),
            'x_frame_options': headers.get('X-Frame-Options', 'Not Set'),
            'x_content_type_options': headers.get('X-Content-Type-Options', 'Not Set'),
            'x_xss_protection': headers.get('X-XSS-Protection', 'Not Set'),
            'referrer_policy': headers.get('Referrer-Policy', 'Not Set'),
            'permissions_policy': headers.get('Permissions-Policy', 'Not Set')
        }
        
        # Security score
        score = 0
        max_score = len(security_headers)
        for header, value in security_headers.items():
            if value != 'Not Set':
                score += 1
        
        security_headers['security_score'] = f"{score}/{max_score}"
        security_headers['grade'] = 'A' if score >= 6 else 'B' if score >= 4 else 'C' if score >= 2 else 'F'
        
        return security_headers
        
    except Exception as e:
        return {'error': f'Could not check security headers: {str(e)}'}

def get_server_info(domain):
    """Get server and hosting information"""
    try:
        response = requests.get(f"https://{domain}", timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        headers = response.headers
        server_info = {
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
            'content_type': headers.get('Content-Type', 'Unknown'),
            'content_encoding': headers.get('Content-Encoding', 'Unknown'),
            'status_code': response.status_code,
            'response_time_ms': int(response.elapsed.total_seconds() * 1000)
        }
        
        # Try to get IP information
        try:
            import socket
            ip = socket.gethostbyname(domain)
            server_info['ip_address'] = ip
            
            # Get location info from IP (using a free service)
            ip_info_response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if ip_info_response.status_code == 200:
                ip_data = ip_info_response.json()
                server_info['location'] = {
                    'country': ip_data.get('country', 'Unknown'),
                    'region': ip_data.get('regionName', 'Unknown'),
                    'city': ip_data.get('city', 'Unknown'),
                    'isp': ip_data.get('isp', 'Unknown'),
                    'org': ip_data.get('org', 'Unknown')
                }
        except:
            pass
            
        return server_info
        
    except Exception as e:
        return {'error': f'Could not get server info: {str(e)}'}

def detect_technologies(domain):
    """Detect technologies used by the website"""
    try:
        response = requests.get(f"https://{domain}", timeout=10, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        technologies = {
            'cms': [],
            'frameworks': [],
            'analytics': [],
            'cdn': [],
            'others': []
        }
        
        content = response.text.lower()
        headers = response.headers
        
        # CMS Detection
        cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', '/wp-json/'],
            'Drupal': ['drupal', 'sites/default', 'misc/drupal.js'],
            'Joomla': ['joomla', 'components/com_', 'templates/system'],
            'Magento': ['magento', 'mage/cookies.js', 'skin/frontend'],
            'Shopify': ['shopify', 'cdn.shopify.com', 'shopify-features'],
            'Wix': ['wix.com', 'wixstatic.com', 'wix-code'],
            'Squarespace': ['squarespace', 'static1.squarespace.com']
        }
        
        for cms, patterns in cms_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies['cms'].append(cms)
        
        # Framework Detection
        framework_patterns = {
            'React': ['react', '_react', 'react-dom'],
            'Vue.js': ['vue.js', '__vue__', 'vue-router'],
            'Angular': ['angular', 'ng-app', 'angularjs'],
            'jQuery': ['jquery', '$.', 'jquery.min.js'],
            'Bootstrap': ['bootstrap', 'btn-primary', 'container-fluid'],
            'Laravel': ['laravel_session', 'laravel', 'csrf-token'],
            'Django': ['django', 'csrfmiddlewaretoken'],
            'Flask': ['flask', 'werkzeug'],
            'Express.js': ['express', 'x-powered-by: express']
        }
        
        for framework, patterns in framework_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies['frameworks'].append(framework)
        
        # Analytics Detection
        analytics_patterns = {
            'Google Analytics': ['google-analytics', 'gtag(', 'googletagmanager'],
            'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
            'Facebook Pixel': ['facebook.net/en_us/fbevents.js', 'fbq('],
            'Hotjar': ['hotjar', 'hjidentify'],
            'Mixpanel': ['mixpanel', 'mp_']
        }
        
        for analytics, patterns in analytics_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies['analytics'].append(analytics)
        
        # CDN Detection
        cdn_patterns = {
            'Cloudflare': ['cloudflare', 'cf-ray', '__cf_bm'],
            'AWS CloudFront': ['cloudfront.net', 'x-amz-cf-id'],
            'MaxCDN': ['maxcdn.com', 'netdna-cdn.com'],
            'KeyCDN': ['keycdn.com'],
            'jsDelivr': ['jsdelivr.net'],
            'cdnjs': ['cdnjs.cloudflare.com']
        }
        
        for cdn, patterns in cdn_patterns.items():
            if any(pattern in content for pattern in patterns):
                technologies['cdn'].append(cdn)
        
        # Check headers for additional info
        server = headers.get('server', '').lower()
        powered_by = headers.get('x-powered-by', '').lower()
        
        if 'nginx' in server:
            technologies['others'].append('Nginx')
        if 'apache' in server:
            technologies['others'].append('Apache')
        if 'cloudflare' in server:
            technologies['cdn'].append('Cloudflare')
        if 'php' in powered_by:
            technologies['frameworks'].append('PHP')
        if 'asp.net' in powered_by:
            technologies['frameworks'].append('ASP.NET')
        
        # Remove duplicates
        for category in technologies:
            technologies[category] = list(set(technologies[category]))
        
        return technologies
        
    except Exception as e:
        return {'error': f'Could not detect technologies: {str(e)}'}

def get_performance_metrics(domain):
    """Get basic performance metrics"""
    try:
        start_time = time.time()
        response = requests.get(f"https://{domain}", timeout=30, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        end_time = time.time()
        
        metrics = {
            'response_time_ms': int((end_time - start_time) * 1000),
            'status_code': response.status_code,
            'content_size_bytes': len(response.content),
            'content_size_kb': round(len(response.content) / 1024, 2),
            'headers_size_bytes': len(str(response.headers)),
            'total_requests': 1,  # This is just the main page
            'compression': 'gzip' if 'gzip' in response.headers.get('content-encoding', '') else 'none'
        }
        
        # Performance grade based on response time
        if metrics['response_time_ms'] < 200:
            metrics['grade'] = 'A+'
        elif metrics['response_time_ms'] < 500:
            metrics['grade'] = 'A'
        elif metrics['response_time_ms'] < 1000:
            metrics['grade'] = 'B'
        elif metrics['response_time_ms'] < 2000:
            metrics['grade'] = 'C'
        else:
            metrics['grade'] = 'F'
        
        return metrics
        
    except Exception as e:
        return {'error': f'Could not get performance metrics: {str(e)}'}
