"""
Correlation Engine - Advanced Pattern Detection
Analyzes multiple OSINT findings together to identify security patterns
"""

import json
from datetime import datetime

class CorrelationEngine:
    """Intelligent pattern detection across multiple data sources"""
    
    def __init__(self):
        self.correlations = []
        self.attack_patterns = []
        
    def analyze(self, osint_data, risk_findings):
        """Perform correlation analysis"""
        
        print(f"\n{'='*60}")
        print(" 🧠 Performing Correlation Analysis")
        print(f"{'='*60}\n")
        
        # Detect attack patterns
        self.detect_dev_db_exposure(osint_data)
        self.detect_admin_weak_security(osint_data)
        self.detect_technology_vulnerabilities(osint_data)
        self.detect_configuration_issues(osint_data)
        self.detect_geographic_anomalies(osint_data)
        self.calculate_attack_surface(osint_data)
        
        # Generate correlation report
        report = {
            'correlations_found': len(self.correlations),
            'attack_patterns': self.attack_patterns,
            'correlations': self.correlations,
            'attack_surface_score': self.calculate_attack_surface_score(osint_data)
        }
        
        self.print_correlation_report(report)
        
        return report
    
    def detect_dev_db_exposure(self, data):
        """Pattern: Development environment + Database port = Critical"""
        
        subdomains = data.get('subdomains', {}).get('found', [])
        ports = data.get('ports', {}).get('details', [])
        
        dev_subs = [s for s in subdomains if any(x in s['subdomain'].lower() for x in ['dev', 'test', 'staging'])]
        db_ports = [p for p in ports if p['port'] in [3306, 5432, 27017, 1433, 6379]]
        
        if dev_subs and db_ports:
            correlation = {
                'id': 'CORR-001',
                'pattern': 'Development Database Exposure',
                'severity': 'CRITICAL',
                'confidence': 85,
                'risk_score': 9.2,
                'indicators': [
                    f"Development subdomain: {', '.join([s['subdomain'] for s in dev_subs[:2]])}",
                    f"Database ports open: {', '.join([str(p['port']) for p in db_ports])}"
                ],
                'attack_vector': 'Attackers can target development databases which often have weaker security controls and may contain production data copies',
                'business_impact': 'Data breach, credential theft, production environment compromise',
                'remediation_priority': 'IMMEDIATE',
                'remediation': [
                    '1. Restrict database ports to internal network only',
                    '2. Remove public DNS records for dev environments',
                    '3. Implement VPN-only access for development systems',
                    '4. Audit what data exists in dev databases',
                    '5. Enable database encryption and strong authentication'
                ],
                'references': [
                    'OWASP Top 10 - Security Misconfiguration',
                    'CWE-16: Configuration'
                ]
            }
            
            self.correlations.append(correlation)
            self.attack_patterns.append('Database Exposure in Non-Production')
            
            print(f"  🔴 CRITICAL: {correlation['pattern']} (confidence: {correlation['confidence']}%)")
    
    def detect_admin_weak_security(self, data):
        """Pattern: Admin interface + No SSL/Weak SSL = High Risk"""
        
        subdomains = data.get('subdomains', {}).get('found', [])
        ssl = data.get('ssl_certificate', {})
        
        admin_subs = [s for s in subdomains if any(x in s['subdomain'].lower() for x in ['admin', 'panel', 'console', 'manage'])]
        
        if admin_subs:
            issues = []
            
            if not ssl.get('valid'):
                issues.append('Invalid or missing SSL certificate')
            
            if issues:
                correlation = {
                    'id': 'CORR-002',
                    'pattern': 'Admin Interface Security Weakness',
                    'severity': 'HIGH',
                    'confidence': 78,
                    'risk_score': 8.1,
                    'indicators': [
                        f"Admin subdomains: {', '.join([s['subdomain'] for s in admin_subs[:2]])}",
                        *issues
                    ],
                    'attack_vector': 'Admin panels without proper SSL expose credentials and session tokens to interception',
                    'business_impact': 'Account takeover, unauthorized access to management functions',
                    'remediation_priority': 'HIGH',
                    'remediation': [
                        '1. Deploy valid SSL/TLS certificates',
                        '2. Enforce HTTPS-only access (HSTS)',
                        '3. Implement IP whitelisting for admin interfaces',
                        '4. Enable multi-factor authentication',
                        '5. Monitor admin access logs'
                    ],
                    'references': [
                        'NIST 800-52: Guidelines for SSL/TLS',
                        'OWASP - Transport Layer Protection'
                    ]
                }
                
                self.correlations.append(correlation)
                self.attack_patterns.append('Weak Admin Interface Security')
                
                print(f"  🟠 HIGH: {correlation['pattern']} (confidence: {correlation['confidence']}%)")
    
    def detect_technology_vulnerabilities(self, data):
        """Pattern: Outdated technology stack = Known vulnerabilities"""
        
        headers = data.get('http_headers', {})
        server = headers.get('server', '').lower()
        
        vulnerable_tech = {
            'apache/2.2': {'severity': 'CRITICAL', 'cves': ['CVE-2017-15710', 'CVE-2017-15715']},
            'apache/2.4.1': {'severity': 'HIGH', 'cves': ['CVE-2017-9798']},
            'nginx/1.0': {'severity': 'HIGH', 'cves': ['CVE-2013-2028']},
            'iis/6.0': {'severity': 'CRITICAL', 'cves': ['CVE-2017-7269']},
            'php/5.': {'severity': 'HIGH', 'cves': ['Multiple - End of Life']},
        }
        
        for tech, vuln_info in vulnerable_tech.items():
            if tech in server:
                correlation = {
                    'id': 'CORR-003',
                    'pattern': 'Vulnerable Technology Stack',
                    'severity': vuln_info['severity'],
                    'confidence': 92,
                    'risk_score': 8.7,
                    'indicators': [
                        f"Server: {headers.get('server')}",
                        f"Known CVEs: {', '.join(vuln_info['cves'][:3])}"
                    ],
                    'attack_vector': 'Outdated server software contains publicly known vulnerabilities with available exploits',
                    'business_impact': 'Remote code execution, full system compromise, data theft',
                    'remediation_priority': 'IMMEDIATE',
                    'remediation': [
                        f"1. Upgrade to latest stable version immediately",
                        f"2. Review CVE database for specific vulnerabilities",
                        f"3. Apply all security patches",
                        f"4. Implement Web Application Firewall (WAF)",
                        f"5. Regular vulnerability scanning"
                    ],
                    'references': [
                        f"CVEs: {', '.join(vuln_info['cves'][:3])}",
                        'NVD: https://nvd.nist.gov/'
                    ]
                }
                
                self.correlations.append(correlation)
                self.attack_patterns.append('Exploitable Technology Stack')
                
                print(f"  🔴 CRITICAL: {correlation['pattern']} - {tech}")
                break
    
    def detect_configuration_issues(self, data):
        """Pattern: Multiple security misconfigurations"""
        
        issues = []
        
        # Check for excessive port exposure
        ports = data.get('ports', {}).get('details', [])
        if len(ports) > 4:
            issues.append(f"Excessive port exposure ({len(ports)} ports open)")
        
        # Check for sensitive ports
        sensitive_ports = [p for p in ports if p['port'] in [22, 23, 21, 3389]]
        if sensitive_ports:
            issues.append(f"Sensitive management ports exposed: {', '.join([str(p['port']) for p in sensitive_ports])}")
        
        # Check for excessive subdomains
        subdomains = data.get('subdomains', {}).get('found', [])
        if len(subdomains) > 15:
            issues.append(f"Large attack surface ({len(subdomains)} subdomains)")
        
        if len(issues) >= 2:
            correlation = {
                'id': 'CORR-004',
                'pattern': 'Multiple Configuration Weaknesses',
                'severity': 'MEDIUM',
                'confidence': 70,
                'risk_score': 6.5,
                'indicators': issues,
                'attack_vector': 'Multiple small misconfigurations create larger attack surface',
                'business_impact': 'Increased risk of successful attack through combined weaknesses',
                'remediation_priority': 'MEDIUM',
                'remediation': [
                    '1. Conduct security hardening review',
                    '2. Close unnecessary ports',
                    '3. Remove unused subdomains',
                    '4. Implement principle of least privilege',
                    '5. Regular security audits'
                ],
                'references': [
                    'CIS Benchmarks',
                    'NIST 800-53: Security Controls'
                ]
            }
            
            self.correlations.append(correlation)
            print(f"  🟡 MEDIUM: {correlation['pattern']}")
    
    def detect_geographic_anomalies(self, data):
        """Pattern: Unexpected geographic location"""
        
        geo = data.get('geolocation', {})
        target = data.get('target', '')
        
        # Geographic expectations
        geo_expectations = {
            '.uk': ['United Kingdom', 'UK'],
            '.de': ['Germany', 'DE'],
            '.fr': ['France', 'FR'],
            '.au': ['Australia', 'AU'],
            '.ca': ['Canada', 'CA'],
        }
        
        for tld, expected_countries in geo_expectations.items():
            if tld in target and geo.get('country') not in expected_countries:
                correlation = {
                    'id': 'CORR-005',
                    'pattern': 'Geographic Location Anomaly',
                    'severity': 'LOW',
                    'confidence': 65,
                    'risk_score': 4.2,
                    'indicators': [
                        f"Domain TLD: {tld}",
                        f"Actual location: {geo.get('country', 'Unknown')}",
                        f"Expected: {', '.join(expected_countries)}"
                    ],
                    'attack_vector': 'Geographic mismatch may indicate compromised infrastructure or data sovereignty issues',
                    'business_impact': 'Potential regulatory compliance violations (GDPR, data residency)',
                    'remediation_priority': 'LOW',
                    'remediation': [
                        '1. Verify hosting location is intentional',
                        '2. Review data protection regulations',
                        '3. Ensure compliance with data residency requirements',
                        '4. Document business justification'
                    ],
                    'references': [
                        'GDPR Article 45: International transfers',
                        'Data sovereignty requirements'
                    ]
                }
                
                self.correlations.append(correlation)
                print(f"  ℹ️  INFO: {correlation['pattern']}")
                break
    
    def calculate_attack_surface(self, data):
        """Calculate overall attack surface metrics"""
        
        attack_surface = {
            'total_endpoints': 0,
            'sensitive_endpoints': 0,
            'exposed_services': 0,
            'data_transmission_security': 'Unknown'
        }
        
        # Count endpoints
        subdomains = data.get('subdomains', {}).get('found', [])
        attack_surface['total_endpoints'] = len(subdomains) + 1  # +1 for main domain
        
        # Count sensitive
        sensitive = [s for s in subdomains if any(x in s['subdomain'].lower() for x in ['admin', 'dev', 'test', 'api'])]
        attack_surface['sensitive_endpoints'] = len(sensitive)
        
        # Count services
        ports = data.get('ports', {}).get('details', [])
        attack_surface['exposed_services'] = len(ports)
        
        # SSL status
        ssl = data.get('ssl_certificate', {})
        attack_surface['data_transmission_security'] = 'Secure' if ssl.get('valid') else 'Insecure'
        
        return attack_surface
    
    def calculate_attack_surface_score(self, data):
        """Calculate numerical attack surface score (0-100)"""
        
        score = 0
        
        # More subdomains = larger attack surface
        subdomains = len(data.get('subdomains', {}).get('found', []))
        score += min(subdomains * 2, 30)  # Max 30 points
        
        # More open ports = more exposure
        ports = len(data.get('ports', {}).get('details', []))
        score += min(ports * 5, 35)  # Max 35 points
        
        # Sensitive subdomains increase score
        sensitive_subs = [s for s in data.get('subdomains', {}).get('found', []) 
                         if any(x in s['subdomain'].lower() for x in ['admin', 'dev', 'test'])]
        score += len(sensitive_subs) * 10  # 10 points each
        
        # No SSL adds points
        if not data.get('ssl_certificate', {}).get('valid'):
            score += 15
        
        return min(score, 100)  # Cap at 100
    
    def print_correlation_report(self, report):
        """Print formatted correlation report"""
        
        print(f"\n{'─'*60}")
        print("📊 Correlation Analysis Results")
        print(f"{'─'*60}\n")
        
        print(f"Correlations Detected: {report['correlations_found']}")
        print(f"Attack Patterns Identified: {len(report['attack_patterns'])}")
        print(f"Attack Surface Score: {report['attack_surface_score']}/100")
        
        if report['attack_patterns']:
            print(f"\n🎯 Attack Patterns:")
            for pattern in report['attack_patterns']:
                print(f"  • {pattern}")
        
        if report['correlations']:
            print(f"\n{'─'*60}")
            print("Detailed Correlations:")
            print(f"{'─'*60}\n")
            
            for corr in report['correlations']:
                severity_icons = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🟢'
                }
                
                icon = severity_icons.get(corr['severity'], '⚪')
                print(f"{icon} [{corr['id']}] {corr['pattern']}")
                print(f"   Severity: {corr['severity']} | Confidence: {corr['confidence']}% | Risk Score: {corr['risk_score']}")
                print(f"\n   Indicators:")
                for indicator in corr['indicators']:
                    print(f"   • {indicator}")
                
                print(f"\n   Attack Vector:")
                print(f"   {corr['attack_vector']}")
                
                print(f"\n   Remediation ({corr['remediation_priority']} Priority):")
                for i, rem in enumerate(corr['remediation'][:3], 1):
                    print(f"   {rem}")
                
                print(f"\n{'─'*60}\n")
        else:
            print("\n✓ No significant security correlations detected")
        
        print(f"{'='*60}\n")


# Test
if __name__ == "__main__":
    # Example usage
    from data_collectors import OSINTCollector
    
    collector = OSINTCollector()
    data = collector.collect_all("google.com", "domain")
    
    engine = CorrelationEngine()
    report = engine.analyze(data, None)
