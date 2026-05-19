"""
Risk Assessment Module
Analyzes OSINT findings and assigns risk levels
"""

class RiskAssessor:
    """Assesses security risks from collected OSINT data"""
    
    def __init__(self):
        self.findings = []
        self.recommendations = []
    
    def assess_all(self, osint_data):
        """
        Assess all collected data and generate risk report
        
        Args:
            osint_data: Dictionary from OSINTCollector.collect_all()
        
        Returns:
            dict: Risk assessment report
        """
        print(f"\n{'='*60}")
        print(" Assessing Security Risks")
        print(f"{'='*60}\n")
        
        target_type = osint_data.get('target_type', 'unknown')
        
        # Assess each data source
        if target_type == 'domain':
            self.assess_dns(osint_data.get('dns', {}))
            self.assess_whois(osint_data.get('whois', {}))
            self.assess_subdomains(osint_data.get('subdomains', {}))
            self.assess_ports(osint_data.get('ports', {}))
        elif target_type == 'email':
            self.assess_email(osint_data.get('email_analysis', {}))
        
        # Calculate overall risk
        overall_risk = self.calculate_overall_risk()
        
        report = {
            'overall_risk': overall_risk,
            'findings': self.findings,
            'recommendations': self.recommendations,
            'summary': self.generate_summary()
        }
        
        self.print_report(report)
        
        return report
    
    def assess_dns(self, dns_data):
        """Assess DNS information"""
        print("→ Assessing DNS information...")
        
        if dns_data.get('resolved'):
            self.findings.append({
                'category': 'Infrastructure',
                'risk_level': 'INFO',
                'title': 'DNS Resolution',
                'description': f"Domain resolves to IP: {dns_data.get('ip_address')}",
                'impact': 'Informational - shows domain is active and reachable'
            })
            print("  ✓ DNS information assessed")
        else:
            self.findings.append({
                'category': 'Infrastructure',
                'risk_level': 'HIGH',
                'title': 'DNS Resolution Failed',
                'description': 'Domain does not resolve to an IP address',
                'impact': 'May indicate domain is inactive, misconfigured, or taken down'
            })
            print("  ⚠ DNS resolution issue detected")
    
    def assess_whois(self, whois_data):
        """Assess WHOIS information"""
        print("→ Assessing WHOIS data...")
        
        if whois_data.get('available'):
            self.findings.append({
                'category': 'Domain Registration',
                'risk_level': 'INFO',
                'title': 'Domain Registration Information',
                'description': f"Registrar: {whois_data.get('registrar', 'Unknown')}",
                'impact': 'Informational - provides ownership context'
            })
            print("  ✓ WHOIS data assessed")
        else:
            # WHOIS unavailable is not a security risk
            print("  ℹ WHOIS data not available (this is common)")
    
    def assess_subdomains(self, subdomain_data):
        """Assess discovered subdomains"""
        print("→ Assessing subdomains...")
        
        count = subdomain_data.get('count', 0)
        found = subdomain_data.get('found', [])
        
        if count == 0:
            self.findings.append({
                'category': 'Attack Surface',
                'risk_level': 'LOW',
                'title': 'Minimal Subdomain Exposure',
                'description': 'No common subdomains discovered',
                'impact': 'Smaller attack surface - good security practice'
            })
            print("  ✓ No subdomains found (good security)")
        
        elif count <= 3:
            self.findings.append({
                'category': 'Attack Surface',
                'risk_level': 'LOW',
                'title': 'Limited Subdomain Exposure',
                'description': f'Found {count} subdomain(s)',
                'impact': 'Small attack surface - acceptable exposure'
            })
            print(f"  ✓ Limited subdomains ({count}) - low risk")
        
        else:
            # Check for sensitive subdomains
            sensitive_names = ['admin', 'test', 'dev', 'staging', 'vpn', 'remote']
            sensitive_found = [s for s in found if any(name in s['subdomain'].lower() for name in sensitive_names)]
            
            if sensitive_found:
                risk_level = 'MEDIUM'
                description = f'Found {count} subdomains including potentially sensitive ones: '
                description += ', '.join([s['subdomain'] for s in sensitive_found[:3]])
                impact = 'Sensitive subdomains (admin, dev, test) may expose management interfaces or development systems'
                
                self.findings.append({
                    'category': 'Attack Surface',
                    'risk_level': risk_level,
                    'title': 'Sensitive Subdomain Exposure',
                    'description': description,
                    'impact': impact
                })
                
                self.recommendations.append({
                    'priority': 'MEDIUM',
                    'category': 'Access Control',
                    'recommendation': 'Restrict access to admin/dev subdomains',
                    'details': 'Use IP whitelisting or VPN for sensitive subdomains. Consider removing public DNS records for internal systems.'
                })
                
                print(f"  ⚠ Sensitive subdomains detected - medium risk")
            else:
                self.findings.append({
                    'category': 'Attack Surface',
                    'risk_level': 'LOW',
                    'title': 'Multiple Subdomains Discovered',
                    'description': f'Found {count} subdomains - all appear to be standard services',
                    'impact': 'Larger attack surface but no obviously sensitive exposures'
                })
                print(f"  ✓ Multiple subdomains ({count}) but no sensitive ones")
    
    def assess_ports(self, port_data):
        """Assess open ports"""
        print("→ Assessing open ports...")
        
        open_count = port_data.get('open', 0)
        details = port_data.get('details', [])
        
        if open_count == 0:
            self.findings.append({
                'category': 'Network Security',
                'risk_level': 'INFO',
                'title': 'No Standard Ports Open',
                'description': 'No common ports detected as open',
                'impact': 'May indicate firewall protection or non-standard configuration'
            })
            print("  ✓ No open ports detected")
        
        elif open_count <= 2:
            # Only web ports (80, 443) is normal
            web_only = all(p['port'] in [80, 443] for p in details)
            
            if web_only:
                self.findings.append({
                    'category': 'Network Security',
                    'risk_level': 'LOW',
                    'title': 'Standard Web Ports Open',
                    'description': 'Only HTTP (80) and/or HTTPS (443) are open',
                    'impact': 'Expected configuration for web servers - minimal risk'
                })
                print("  ✓ Only standard web ports open - low risk")
            else:
                self.findings.append({
                    'category': 'Network Security',
                    'risk_level': 'MEDIUM',
                    'title': 'Limited Port Exposure',
                    'description': f'{open_count} ports open: ' + ', '.join([f"{p['port']} ({p['service']})" for p in details]),
                    'impact': 'Additional services exposed beyond web traffic'
                })
                print(f"  ℹ {open_count} ports open")
        
        else:
            # Multiple ports open - check for risky ones
            risky_ports = [p for p in details if p['port'] in [21, 22, 23, 3306, 5432]]
            
            if risky_ports:
                risk_level = 'HIGH'
                description = f'{open_count} ports open including sensitive services: '
                description += ', '.join([f"{p['port']} ({p['service']})" for p in risky_ports])
                impact = 'Database or management ports exposed to internet - significant security risk'
                
                self.findings.append({
                    'category': 'Network Security',
                    'risk_level': risk_level,
                    'title': 'Sensitive Ports Exposed',
                    'description': description,
                    'impact': impact
                })
                
                self.recommendations.append({
                    'priority': 'HIGH',
                    'category': 'Network Security',
                    'recommendation': 'Close or restrict access to sensitive ports',
                    'details': 'Ports like SSH (22), FTP (21), MySQL (3306) should not be publicly accessible. Use firewall rules or VPN access.'
                })
                
                print(f"  ⚠ HIGH RISK: Sensitive ports exposed!")
            else:
                self.findings.append({
                    'category': 'Network Security',
                    'risk_level': 'MEDIUM',
                    'title': 'Multiple Ports Open',
                    'description': f'{open_count} ports are open',
                    'impact': 'Larger attack surface - each open port is a potential entry point'
                })
                print(f"  ⚠ Multiple ports open ({open_count}) - medium risk")
    
    def assess_email(self, email_data):
        """Assess email information"""
        print("→ Assessing email information...")
        
        if email_data.get('domain'):
            self.findings.append({
                'category': 'Email Analysis',
                'risk_level': 'INFO',
                'title': 'Email Domain Identified',
                'description': f"Email uses domain: {email_data.get('domain')}",
                'impact': 'Informational - shows email provider'
            })
            print("  ✓ Email information assessed")
    
    def calculate_overall_risk(self):
        """Calculate overall risk level from all findings"""
        
        if not self.findings:
            return 'LOW'
        
        risk_scores = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        
        max_risk = max([risk_scores.get(f['risk_level'], 0) for f in self.findings])
        
        if max_risk >= 3:
            return 'HIGH'
        elif max_risk >= 2:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_summary(self):
        """Generate summary statistics"""
        
        high_count = len([f for f in self.findings if f['risk_level'] == 'HIGH'])
        medium_count = len([f for f in self.findings if f['risk_level'] == 'MEDIUM'])
        low_count = len([f for f in self.findings if f['risk_level'] == 'LOW'])
        
        return {
            'total_findings': len(self.findings),
            'high_risk': high_count,
            'medium_risk': medium_count,
            'low_risk': low_count,
            'recommendations': len(self.recommendations)
        }
    
    def print_report(self, report):
        """Print formatted risk report"""
        
        print(f"\n{'='*60}")
        print(" Risk Assessment Report")
        print(f"{'='*60}\n")
        
        # Overall risk
        risk = report['overall_risk']
        risk_colors = {'HIGH': '🔴', 'MEDIUM': '🟡', 'LOW': '🟢'}
        print(f"Overall Risk Level: {risk_colors.get(risk, '⚪')} {risk}\n")
        
        # Summary
        summary = report['summary']
        print(f"Total Findings: {summary['total_findings']}")
        print(f"  • High Risk: {summary['high_risk']}")
        print(f"  • Medium Risk: {summary['medium_risk']}")
        print(f"  • Low Risk: {summary['low_risk']}")
        print(f"Recommendations: {summary['recommendations']}\n")
        
        # Findings
        if report['findings']:
            print(f"{'─'*60}")
            print("Detailed Findings:")
            print(f"{'─'*60}\n")
            
            for i, finding in enumerate(report['findings'], 1):
                risk_icon = risk_colors.get(finding['risk_level'], '⚪')
                print(f"{i}. [{risk_icon} {finding['risk_level']}] {finding['title']}")
                print(f"   Category: {finding['category']}")
                print(f"   {finding['description']}")
                print(f"   Impact: {finding['impact']}\n")
        
        # Recommendations
        if report['recommendations']:
            print(f"{'─'*60}")
            print("Recommendations:")
            print(f"{'─'*60}\n")
            
            for i, rec in enumerate(report['recommendations'], 1):
                print(f"{i}. [{rec['priority']}] {rec['recommendation']}")
                print(f"   {rec['details']}\n")
        
        print(f"{'='*60}")


# Test the module
if __name__ == "__main__":
    from data_collectors import OSINTCollector
    
    print("\n" + "="*60)
    print(" Testing Risk Assessment Module")
    print("="*60)
    
    # Collect data
    collector = OSINTCollector()
    osint_data = collector.collect_all("google.com", "domain")
    
    # Assess risks
    assessor = RiskAssessor()
    risk_report = assessor.assess_all(osint_data)
    
    print("\n✅ Risk assessment complete!")
