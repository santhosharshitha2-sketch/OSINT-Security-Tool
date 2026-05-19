"""
OSINT Data Collection Module - ENHANCED VERSION
Collects from multiple sources: DNS, WHOIS, Subdomains, Ports, 
Shodan, VirusTotal, SSL Certificates, HTTP Headers, Geolocation
"""

import socket
import subprocess
import requests
import ssl
import json
from datetime import datetime

class OSINTCollector:
    """Enhanced OSINT collector with multiple data sources"""
    
    def __init__(self, shodan_api_key=None, virustotal_api_key=None):
        self.results = {}
        self.target = None
        self.target_type = None
        self.shodan_api_key = shodan_api_key
        self.virustotal_api_key = virustotal_api_key
    
    def collect_all(self, target, target_type='domain'):
        """Collect data from ALL available sources"""
        self.target = target
        self.target_type = target_type
        
        print(f"\n{'='*60}")
        print(f" Collecting OSINT data for: {target}")
        print(f" Type: {target_type}")
        print(f"{'='*60}\n")
        
        if target_type == 'domain':
            # Original sources
            self.collect_dns_info()
            self.collect_whois_info()
            self.collect_subdomains()
            self.collect_port_info()
            
            # NEW sources
            self.collect_http_headers()
            self.collect_ssl_certificate()
            self.collect_geolocation()
            self.collect_reverse_dns()
            self.collect_mx_records()
            
            # API-based (if keys provided)
            if self.shodan_api_key:
                self.collect_shodan_info()
            if self.virustotal_api_key:
                self.collect_virustotal_info()
        
        elif target_type == 'email':
            self.collect_email_info()
            self.validate_email_format()
            
        self.results['collection_time'] = datetime.now().isoformat()
        self.results['target'] = target
        self.results['target_type'] = target_type
        self.results['sources_used'] = list(self.results.keys())
        
        return self.results
    
    def collect_dns_info(self):
        """Collect DNS information"""
        print("→ Collecting DNS information...")
        
        try:
            ip = socket.gethostbyname(self.target)
            
            hostname = None
            try:
                hostname_data = socket.gethostbyaddr(ip)
                hostname = hostname_data[0]
            except:
                pass
            
            self.results['dns'] = {
                'ip_address': ip,
                'hostname': hostname,
                'resolved': True
            }
            
            print(f"  ✓ IP: {ip}")
            if hostname:
                print(f"  ✓ Hostname: {hostname}")
            
        except Exception as e:
            self.results['dns'] = {
                'error': str(e),
                'resolved': False
            }
            print(f"  ✗ DNS lookup failed: {e}")
    
    def collect_whois_info(self):
        """Collect WHOIS information"""
        print("→ Collecting WHOIS information...")
        
        try:
            result = subprocess.run(['whois', self.target],
                                  capture_output=True,
                                  text=True,
                                  timeout=5)
            
            if result.returncode == 0:
                output = result.stdout
                
                registrar = None
                creation_date = None
                expiry_date = None
                
                for line in output.split('\n'):
                    if 'Registrar:' in line and not registrar:
                        registrar = line.split(':', 1)[1].strip()
                    if 'Creation Date:' in line and not creation_date:
                        creation_date = line.split(':', 1)[1].strip()
                    if 'Expiry Date:' in line or 'Registry Expiry Date:' in line:
                        if not expiry_date:
                            expiry_date = line.split(':', 1)[1].strip()
                
                self.results['whois'] = {
                    'registrar': registrar,
                    'creation_date': creation_date,
                    'expiry_date': expiry_date,
                    'available': True
                }
                
                print(f"  ✓ WHOIS data retrieved")
                if registrar:
                    print(f"    Registrar: {registrar}")
            
        except subprocess.TimeoutExpired:
            self.results['whois'] = {'available': False, 'reason': 'timeout'}
            print("  ⚠ WHOIS timeout (skipped)")
        except Exception as e:
            self.results['whois'] = {'available': False, 'error': str(e)}
            print(f"  ⚠ WHOIS unavailable: {e}")
    
    def collect_subdomains(self):
        """Enumerate common subdomains"""
        print("→ Enumerating subdomains...")
        
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 
                       'test', 'staging', 'vpn', 'remote', 'blog',
                       'shop', 'forum', 'support', 'help', 'portal']
        
        found = []
        
        for sub in common_subs:
            full_domain = f"{sub}.{self.target}"
            try:
                ip = socket.gethostbyname(full_domain)
                found.append({'subdomain': full_domain, 'ip': ip})
            except:
                pass
        
        self.results['subdomains'] = {
            'count': len(found),
            'found': found
        }
        
        print(f"  ✓ Found {len(found)} subdomain(s)")
        for item in found[:3]:
            print(f"    • {item['subdomain']} -> {item['ip']}")
        if len(found) > 3:
            print(f"    ... and {len(found) - 3} more")
    
    def collect_port_info(self):
        """Scan common ports"""
        print("→ Scanning common ports...")
        
        ports_to_check = {
            80: 'HTTP', 443: 'HTTPS', 22: 'SSH', 21: 'FTP',
            25: 'SMTP', 3306: 'MySQL', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 3389: 'RDP',
            23: 'Telnet', 53: 'DNS', 110: 'POP3', 143: 'IMAP'
        }
        
        open_ports = []
        
        try:
            ip = socket.gethostbyname(self.target)
            
            for port, service in ports_to_check.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append({'port': port, 'service': service, 'status': 'open'})
                sock.close()
            
            self.results['ports'] = {
                'scanned': len(ports_to_check),
                'open': len(open_ports),
                'details': open_ports
            }
            
            print(f"  ✓ Found {len(open_ports)} open port(s)")
            for item in open_ports:
                print(f"    • Port {item['port']} ({item['service']})")
                
        except Exception as e:
            self.results['ports'] = {'error': str(e)}
            print(f"  ✗ Port scan error: {e}")
    
    def collect_http_headers(self):
        """Collect HTTP headers to detect technologies"""
        print("→ Collecting HTTP headers...")
        
        try:
            url = f"http://{self.target}"
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            headers = dict(response.headers)
            
            self.results['http_headers'] = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Unknown'),
                'content_type': headers.get('Content-Type', 'Unknown'),
                'status_code': response.status_code,
                'redirect': response.url if response.url != url else None
            }
            
            print(f"  ✓ HTTP headers retrieved")
            print(f"    Server: {headers.get('Server', 'Unknown')}")
            
        except Exception as e:
            self.results['http_headers'] = {'error': str(e)}
            print(f"  ⚠ HTTP headers unavailable: {e}")
    
    def collect_ssl_certificate(self):
        """Collect SSL certificate information"""
        print("→ Collecting SSL certificate...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['ssl_certificate'] = {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'valid': True
                    }
                    
                    print(f"  ✓ SSL certificate valid")
                    print(f"    Issuer: {dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown')}")
        
        except Exception as e:
            self.results['ssl_certificate'] = {'error': str(e), 'valid': False}
            print(f"  ⚠ SSL certificate unavailable: {e}")
    
    def collect_geolocation(self):
        """Get geolocation of IP address"""
        print("→ Getting geolocation...")
        
        try:
            ip = self.results.get('dns', {}).get('ip_address')
            if not ip:
                raise Exception("No IP address available")
            
            # Using free ip-api.com service
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = response.json()
            
            if data['status'] == 'success':
                self.results['geolocation'] = {
                    'country': data.get('country'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon')
                }
                
                print(f"  ✓ Location: {data.get('city')}, {data.get('country')}")
                print(f"    ISP: {data.get('isp')}")
            
        except Exception as e:
            self.results['geolocation'] = {'error': str(e)}
            print(f"  ⚠ Geolocation unavailable: {e}")
    
    def collect_reverse_dns(self):
        """Perform reverse DNS lookup"""
        print("→ Reverse DNS lookup...")
        
        try:
            ip = self.results.get('dns', {}).get('ip_address')
            if not ip:
                raise Exception("No IP address available")
            
            hostname = socket.gethostbyaddr(ip)
            
            self.results['reverse_dns'] = {
                'hostname': hostname[0],
                'aliases': hostname[1]
            }
            
            print(f"  ✓ Reverse DNS: {hostname[0]}")
        
        except Exception as e:
            self.results['reverse_dns'] = {'error': str(e)}
            print(f"  ⚠ Reverse DNS failed")
    
    def collect_mx_records(self):
        """Collect MX (mail server) records"""
        print("→ Collecting MX records...")
        
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(self.target, 'MX')
            
            mx_list = []
            for mx in mx_records:
                mx_list.append({
                    'priority': mx.preference,
                    'server': str(mx.exchange)
                })
            
            self.results['mx_records'] = {
                'count': len(mx_list),
                'servers': mx_list
            }
            
            print(f"  ✓ Found {len(mx_list)} MX record(s)")
            for mx in mx_list[:2]:
                print(f"    • {mx['server']} (priority: {mx['priority']})")
        
        except ImportError:
            print("  ℹ Install dnspython: pip install dnspython")
            self.results['mx_records'] = {'error': 'dnspython not installed'}
        except Exception as e:
            self.results['mx_records'] = {'error': str(e)}
            print(f"  ⚠ MX records unavailable")
    
    def collect_shodan_info(self):
        """Collect data from Shodan API"""
        print("→ Querying Shodan...")
        
        try:
            ip = self.results.get('dns', {}).get('ip_address')
            if not ip:
                raise Exception("No IP address available")
            
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {'key': self.shodan_api_key}
            
            response = requests.get(url, params=params, timeout=10)
            data = response.json()
            
            self.results['shodan'] = {
                'ports': data.get('ports', []),
                'vulns': data.get('vulns', []),
                'os': data.get('os'),
                'organization': data.get('org'),
                'last_update': data.get('last_update')
            }
            
            print(f"  ✓ Shodan data retrieved")
            print(f"    Open ports: {len(data.get('ports', []))}")
            if data.get('vulns'):
                print(f"    Vulnerabilities: {len(data.get('vulns', []))}")
        
        except Exception as e:
            self.results['shodan'] = {'error': str(e)}
            print(f"  ⚠ Shodan query failed: {e}")
    
    def collect_virustotal_info(self):
        """Collect data from VirusTotal API"""
        print("→ Querying VirusTotal...")
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.target}"
            headers = {'x-apikey': self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            data = response.json()
            
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            self.results['virustotal'] = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'clean': stats.get('harmless', 0),
                'undetected': stats.get('undetected', 0),
                'reputation': data.get('data', {}).get('attributes', {}).get('reputation', 0)
            }
            
            print(f"  ✓ VirusTotal data retrieved")
            if stats.get('malicious', 0) > 0:
                print(f"    ⚠ Flagged as malicious by {stats['malicious']} vendors")
            else:
                print(f"    ✓ No malicious flags")
        
        except Exception as e:
            self.results['virustotal'] = {'error': str(e)}
            print(f"  ⚠ VirusTotal query failed: {e}")
    
    def collect_email_info(self):
        """Collect information about email address"""
        print("→ Analyzing email address...")
        
        if '@' in self.target:
            domain = self.target.split('@')[1]
            username = self.target.split('@')[0]
            
            self.results['email_analysis'] = {
                'email': self.target,
                'username': username,
                'domain': domain
            }
            
            print(f"  ✓ Username: {username}")
            print(f"  ✓ Domain: {domain}")
            
            # Also collect domain info
            original_target = self.target
            self.target = domain
            self.collect_dns_info()
            self.collect_mx_records()
            self.target = original_target
        else:
            self.results['email_analysis'] = {'error': 'Invalid email format'}
            print("  ✗ Invalid email format")
    
    def validate_email_format(self):
        """Validate email format"""
        print("→ Validating email format...")
        
        import re
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        is_valid = bool(re.match(email_regex, self.target))
        
        self.results['email_validation'] = {
            'valid_format': is_valid,
            'has_mx_records': bool(self.results.get('mx_records', {}).get('count', 0) > 0)
        }
        
        if is_valid:
            print(f"  ✓ Email format is valid")
        else:
            print(f"  ✗ Email format is invalid")


# Test the enhanced module
if __name__ == "__main__":
    print("\n" + "="*60)
    print(" Testing Enhanced OSINT Collection Module")
    print("="*60)
    
    
    SHODAN_KEY = None  
    VT_KEY = None      
    
    collector = OSINTCollector(
        shodan_api_key=SHODAN_KEY,
        virustotal_api_key=VT_KEY
    )
    
    results = collector.collect_all("google.com", "domain")
    
    print("\n" + "="*60)
    print(" Collection Complete!")
    print("="*60)
    print(f"\nData sources collected: {len(results['sources_used'])}")
    for source in results['sources_used']:
        if source not in ['collection_time', 'target', 'target_type', 'sources_used']:
            print(f"  • {source}")
