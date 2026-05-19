"""
Email Fraud Detection Module
Identifies disposable/temporary email addresses and assesses email trustworthiness
"""

import re
import socket
import dns.resolver
from datetime import datetime


class EmailFraudDetector:
    """
    Detects fraudulent, disposable, or suspicious email addresses
    through pattern analysis and domain reputation scoring
    """
    
    def __init__(self):
        # Known disposable/temporary email services
        self.disposable_domains = [
            # Popular temporary email services
            'tempmail.com', 'temp-mail.org', 'temp-mail.io',
            'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org',
            '10minutemail.com', '10minutemail.net',
            'throwaway.email', 'throwawaymail.com',
            'mailinator.com', 'mailinator2.com',
            'trashmail.com', 'trash-mail.com',
            'yopmail.com', 'yopmail.net',
            'maildrop.cc', 'maildrop.cf',
            'getnada.com', 'getairmail.com',
            'fakeinbox.com', 'fakemail.net',
            'sharklasers.com', 'grr.la',
            'dispostable.com', 'disposablemail.com',
            'emailondeck.com', 'incognitomail.org',
            'mintemail.com', 'mytemp.email',
            'spamgourmet.com', 'trashmail.ws',
            'mohmal.com', 'mymailcheap.com',
            'tempinbox.com', 'tempr.email',
            'mailcatch.com', 'mailnesia.com',
            'mailsac.com', 'anonbox.net',
            'spambox.us', 'spamfree24.org',
            'mailexpire.com', 'emailsensei.com',
            'burnermail.io', 'anonymousemail.me',
            'deadaddress.com', 'discard.email',
            'fakemail.fr', 'filzmail.com',
            'gishpuppy.com', 'inbox.si',
            'jetable.org', 'klzlk.com',
            'owlpic.com', 'proxymail.eu',
            'sogetthis.com', 'tempemail.co.za',
            'tmpmail.net', 'trbvm.com',
            'wegwerfmail.de', 'wegwerfemail.de',
            'zehnminuten.de', 'zippymail.info',
            
            # The one you discovered
            'duoley.com',
            
            # Additional suspicious services
            'mailforspam.com', 'spamhereplease.com',
            'spamthisplease.com', 'bccto.me',
            'bobmail.info', 'chogmail.com',
            'cool.fr.nf', 'dropmail.me',
            'email60.com', 'emailias.com',
            'emeil.in', 'emltmp.com',
            'getonemail.com', 'harakirimail.com',
            'hidemail.de', 'instant-mail.de',
            'ip6.li', 'koszmail.pl',
            'mailbidon.com', 'maileater.com',
            'mailme.ir', 'meltmail.com',
            'moakt.com', 'mytrashmail.com',
            'nospam.ze.tc', 'nowmymail.com',
            'objectmail.com', 'obobbo.com',
            'oneoffemail.com', 'pookmail.com',
            'proxymail.eu', 'put2.net',
            'rcpt.at', 'recode.me',
            'rmqkr.net', 's0ny.net',
            'safe-mail.net', 'safetymail.info',
            'selfdestructingmail.com', 'shortmail.net',
            'spam4.me', 'spaml.de',
            'tempemail.net', 'tempinbox.co.uk',
            'tempmail.eu', 'tempmailer.com',
            'tempmailer.de', 'tempomail.fr',
            'tfwno.gf', 'thankyou2010.com',
            'throwawayemailaddress.com', 'tmail.ws',
            'tmailinator.com', 'tradermail.info',
            'trash2009.com', 'trashinbox.net',
            'trillianpro.com', 'twinmail.de',
            'uggsrock.com', 'venompen.com',
            'veryrealemail.com', 'viditag.com',
            'viewcastmedia.com', 'webemail.me',
            'wh4f.org', 'whatiaas.com',
            'whyspam.me', 'willselfdestruct.com',
            'winemaven.info', 'wronghead.com',
            'wuzup.net', 'wuzupmail.net',
            'xagloo.com', 'xemaps.com',
            'xents.com', 'xoxy.net',
            'yopmail.fr', 'yuurok.com',
            'zehnminutenmail.de', 'zoemail.com'
        ]
        
        # Trusted email providers (whitelist)
        self.trusted_providers = [
            # Major providers
            'gmail.com', 'googlemail.com',
            'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
            'yahoo.com', 'yahoo.co.uk', 'ymail.com',
            'icloud.com', 'me.com', 'mac.com',
            'aol.com',
            
            # Privacy-focused
            'protonmail.com', 'protonmail.ch', 'pm.me',
            'tutanota.com', 'tutanota.de',
            'mailfence.com',
            'posteo.de', 'posteo.net',
            
            # Business
            'zoho.com', 'zohomail.com',
            'fastmail.com',
            'gmx.com', 'gmx.net',
            'mail.com',
            
            # Regional
            'btinternet.com', 'virginmedia.com',
            'sky.com', 'talktalk.net',
            'web.de', 't-online.de',
            'orange.fr', 'laposte.net',
            'libero.it', 'alice.it'
        ]
    
    def analyze_email(self, email, email_data=None):
        """
        Comprehensive email fraud analysis
        
        Args:
            email: Email address to analyze
            email_data: Optional - existing data from data_collectors module
        
        Returns:
            Dictionary with fraud analysis results
        """
        
        # Parse email
        if '@' not in email:
            return {
                'valid': False,
                'error': 'Invalid email format'
            }
        
        username, domain = email.split('@', 1)
        
        # Run all checks
        disposable_check = self.check_disposable_domain(domain)
        username_analysis = self.analyze_username_pattern(username)
        domain_trust = self.check_domain_trustworthiness(domain, email_data)
        
        # Calculate overall fraud score (0-100, higher = more suspicious)
        fraud_score = self.calculate_fraud_score(
            disposable_check, 
            username_analysis, 
            domain_trust
        )
        
        # Determine risk level
        risk_level = self.determine_risk_level(fraud_score)
        
        # Generate findings
        findings = self.generate_findings(
            disposable_check,
            username_analysis,
            domain_trust,
            fraud_score
        )
        
        return {
            'email': email,
            'username': username,
            'domain': domain,
            'disposable_check': disposable_check,
            'username_analysis': username_analysis,
            'domain_trust': domain_trust,
            'fraud_score': fraud_score,
            'risk_level': risk_level,
            'findings': findings,
            'recommendation': self.get_recommendation(risk_level, fraud_score)
        }
    
    def check_disposable_domain(self, domain):
        """
        Check if domain is a known disposable email service
        """
        
        domain_lower = domain.lower()
        
        if domain_lower in self.disposable_domains:
            return {
                'is_disposable': True,
                'confidence': 100,
                'service_type': 'Known temporary email service',
                'risk': 'CRITICAL'
            }
        
        # Check for variations (e.g., subdomain.tempmail.com)
        for disposable in self.disposable_domains:
            if domain_lower.endswith('.' + disposable):
                return {
                    'is_disposable': True,
                    'confidence': 95,
                    'service_type': 'Subdomain of known temporary service',
                    'risk': 'HIGH'
                }
        
        # Check for suspicious patterns in domain name
        suspicious_keywords = [
            'temp', 'trash', 'throw', 'fake', 'spam',
            'disposable', 'guerrilla', 'burner', 'anon',
            'discard', 'temporary', 'mailinator'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                return {
                    'is_disposable': 'LIKELY',
                    'confidence': 75,
                    'service_type': 'Suspicious domain name pattern',
                    'risk': 'HIGH'
                }
        
        # Not identified as disposable
        return {
            'is_disposable': False,
            'confidence': 0,
            'service_type': None,
            'risk': 'LOW'
        }
    
    def analyze_username_pattern(self, username):
        """
        Analyze username for random generation patterns
        """
        
        username_lower = username.lower()
        
        # Pattern 1: Many letters followed by many numbers (e.g., yayih16339)
        pattern1 = re.match(r'^[a-z]{4,}\d{4,}$', username_lower)
        if pattern1:
            return {
                'pattern': 'randomly_generated',
                'pattern_type': 'letters_then_numbers',
                'confidence': 85,
                'example': 'yayih16339',
                'risk': 'HIGH'
            }
        
        # Pattern 2: All numbers (e.g., 123456789)
        pattern2 = re.match(r'^\d{6,}$', username_lower)
        if pattern2:
            return {
                'pattern': 'randomly_generated',
                'pattern_type': 'all_numbers',
                'confidence': 90,
                'example': '123456789',
                'risk': 'HIGH'
            }
        
        # Pattern 3: Short letters + many numbers (e.g., ab123456)
        pattern3 = re.match(r'^[a-z]{1,3}\d{5,}$', username_lower)
        if pattern3:
            return {
                'pattern': 'randomly_generated',
                'pattern_type': 'short_prefix_numbers',
                'confidence': 80,
                'example': 'ab123456',
                'risk': 'MEDIUM'
            }
        
        # Pattern 4: Random character mix (e.g., a1b2c3d4e5)
        if len(username_lower) > 10:
            alpha_count = sum(c.isalpha() for c in username_lower)
            digit_count = sum(c.isdigit() for c in username_lower)
            
            if alpha_count > 0 and digit_count > 0 and alpha_count == digit_count:
                return {
                    'pattern': 'possibly_random',
                    'pattern_type': 'alternating_chars',
                    'confidence': 65,
                    'example': 'a1b2c3d4',
                    'risk': 'MEDIUM'
                }
        
        # Pattern 5: Very long random-looking string
        if len(username_lower) > 15 and any(char.isdigit() for char in username_lower):
            return {
                'pattern': 'possibly_random',
                'pattern_type': 'very_long_mixed',
                'confidence': 60,
                'example': 'verylongrandomstring123',
                'risk': 'MEDIUM'
            }
        
        # Pattern 6: Common spam patterns
        spam_patterns = ['noreply', 'no-reply', 'donotreply', 'test', 'admin123']
        if username_lower in spam_patterns:
            return {
                'pattern': 'suspicious',
                'pattern_type': 'common_spam_pattern',
                'confidence': 70,
                'risk': 'MEDIUM'
            }
        
        # Looks normal
        return {
            'pattern': 'normal',
            'pattern_type': 'appears_legitimate',
            'confidence': 0,
            'risk': 'LOW'
        }
    
    def check_domain_trustworthiness(self, domain, email_data=None):
        """
        Assess domain trustworthiness and reputation
        """
        
        domain_lower = domain.lower()
        
        # Check if trusted provider
        if domain_lower in self.trusted_providers:
            return {
                'trust_level': 'HIGH',
                'reason': 'Well-known, reputable email provider',
                'risk': 'LOW',
                'dns_resolves': True
            }
        
        # Check DNS resolution (from email_data if available)
        dns_resolves = True
        if email_data:
            dns_data = email_data.get('dns', {})
            dns_resolves = dns_data.get('resolved', False)
        else:
            # Try to resolve ourselves
            try:
                socket.gethostbyname(domain)
                dns_resolves = True
            except:
                dns_resolves = False
        
        # Non-resolving domain = very suspicious
        if not dns_resolves:
            return {
                'trust_level': 'CRITICAL',
                'reason': 'Domain does not resolve - likely fake or inactive',
                'risk': 'CRITICAL',
                'dns_resolves': False
            }
        
        # Check MX records (from email_data if available)
        has_mx_records = True
        mx_count = 0
        
        if email_data:
            mx_data = email_data.get('mx_records', {})
            mx_count = mx_data.get('count', 0)
            has_mx_records = mx_count > 0
        else:
            # Try to check ourselves
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_count = len(list(mx_records))
                has_mx_records = mx_count > 0
            except:
                has_mx_records = False
        
        # No MX records = can't receive email
        if not has_mx_records:
            return {
                'trust_level': 'HIGH_RISK',
                'reason': 'No MX records - cannot receive email',
                'risk': 'HIGH',
                'dns_resolves': dns_resolves,
                'mx_records': False
            }
        
        # Domain characteristics analysis
        domain_age_suspicious = False
        
        # Very short domain names (< 5 chars) can be suspicious
        if len(domain_lower.split('.')[0]) < 5:
            domain_age_suspicious = True
        
        # New or obscure TLDs
        tld = domain_lower.split('.')[-1]
        suspicious_tlds = ['xyz', 'top', 'work', 'click', 'link', 'tk', 'ml', 'ga', 'cf', 'gq']
        
        if tld in suspicious_tlds:
            return {
                'trust_level': 'MEDIUM',
                'reason': f'Suspicious TLD (.{tld}) often used for temporary services',
                'risk': 'MEDIUM',
                'dns_resolves': dns_resolves,
                'mx_records': has_mx_records
            }
        
        # Corporate/business domains (common TLDs, reasonable length)
        if tld in ['com', 'org', 'net', 'edu', 'gov'] and len(domain_lower.split('.')[0]) >= 5:
            return {
                'trust_level': 'MEDIUM',
                'reason': 'Appears to be legitimate business/organization domain',
                'risk': 'LOW',
                'dns_resolves': dns_resolves,
                'mx_records': has_mx_records
            }
        
        # Default: Unknown but not obviously suspicious
        return {
            'trust_level': 'UNKNOWN',
            'reason': 'Unknown email provider - manual verification recommended',
            'risk': 'MEDIUM',
            'dns_resolves': dns_resolves,
            'mx_records': has_mx_records
        }
    
    def calculate_fraud_score(self, disposable_check, username_analysis, domain_trust):
        """
        Calculate overall fraud score (0-100, higher = more fraudulent)
        """
        
        score = 0
        
        # Disposable domain (0-50 points)
        if disposable_check['is_disposable'] == True:
            score += 50
        elif disposable_check['is_disposable'] == 'LIKELY':
            score += 35
        
        # Username pattern (0-25 points)
        if username_analysis['pattern'] == 'randomly_generated':
            score += username_analysis['confidence'] * 0.40
        elif username_analysis['pattern'] == 'possibly_random':
            score += username_analysis['confidence'] * 0.15  # Max 15 points
        
        # Domain trust (0-25 points)
        trust_penalties = {
            'CRITICAL': 25,
            'HIGH_RISK': 20,
            'MEDIUM': 10,
            'UNKNOWN': 15,
            'HIGH': 0
        }
        score += trust_penalties.get(domain_trust['trust_level'], 10)
        
        return min(int(score), 100)
    
    def determine_risk_level(self, fraud_score):
        """
        Determine overall risk level based on fraud score
        """
        
        if fraud_score >= 75:
            return 'CRITICAL'
        elif fraud_score >= 50:
            return 'HIGH'
        elif fraud_score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def generate_findings(self, disposable_check, username_analysis, domain_trust, fraud_score):
        """
        Generate human-readable findings
        """
        
        findings = []
        
        # Disposable email finding
        if disposable_check['is_disposable'] == True:
            findings.append({
                'category': 'Email Fraud',
                'severity': 'CRITICAL',
                'title': 'Disposable Email Service Detected',
                'description': f"Email uses {disposable_check['service_type']}: {disposable_check.get('domain', 'unknown')}",
                'impact': 'Temporary emails are often used for fraud, spam, or avoiding accountability',
                'confidence': disposable_check['confidence']
            })
        elif disposable_check['is_disposable'] == 'LIKELY':
            findings.append({
                'category': 'Email Fraud',
                'severity': 'HIGH',
                'title': 'Likely Disposable Email Service',
                'description': disposable_check['service_type'],
                'impact': 'Domain name suggests temporary email service',
                'confidence': disposable_check['confidence']
            })
        
        # Random username finding
        if username_analysis['pattern'] in ['randomly_generated', 'possibly_random']:
            severity = 'HIGH' if username_analysis['confidence'] > 75 else 'MEDIUM'
            findings.append({
                'category': 'Email Authenticity',
                'severity': severity,
                'title': 'Randomly Generated Username Pattern',
                'description': f"Username matches pattern: {username_analysis['pattern_type']} (confidence: {username_analysis['confidence']}%)",
                'impact': 'May indicate automated account creation or throwaway account',
                'confidence': username_analysis['confidence']
            })
        
        # Domain trust finding
        if domain_trust['trust_level'] in ['CRITICAL', 'HIGH_RISK', 'MEDIUM']:
            severity_map = {
                'CRITICAL': 'CRITICAL',
                'HIGH_RISK': 'HIGH',
                'MEDIUM': 'MEDIUM'
            }
            findings.append({
                'category': 'Domain Trust',
                'severity': severity_map[domain_trust['trust_level']],
                'title': f"Domain Trustworthiness: {domain_trust['trust_level']}",
                'description': domain_trust['reason'],
                'impact': 'Unknown or suspicious email domains may indicate malicious intent',
                'dns_resolves': domain_trust.get('dns_resolves', False),
                'mx_records': domain_trust.get('mx_records', False)
            })
        
        return findings
    
    def get_recommendation(self, risk_level, fraud_score):
        """
        Generate action recommendation based on risk level
        """
        
        recommendations = {
            'CRITICAL': {
                'action': 'REJECT',
                'description': 'High probability of fraudulent email - recommend rejection',
                'details': [
                    'Do not accept this email for account registration',
                    'Flag for manual review if already registered',
                    'Consider blocking domain entirely',
                    'Report to fraud prevention system'
                ]
            },
            'HIGH': {
                'action': 'REVIEW',
                'description': 'Suspicious email - requires manual verification',
                'details': [
                    'Require additional verification (phone, ID)',
                    'Monitor account activity closely',
                    'Implement stricter security controls',
                    'Consider temporary restrictions'
                ]
            },
            'MEDIUM': {
                'action': 'ACCEPT_WITH_CAUTION',
                'description': 'Potentially suspicious - proceed with standard verification',
                'details': [
                    'Apply standard verification procedures',
                    'Monitor for unusual activity',
                    'Log for future analysis',
                    'Consider email verification required'
                ]
            },
            'LOW': {
                'action': 'ACCEPT',
                'description': 'Email appears legitimate',
                'details': [
                    'Proceed with normal account creation',
                    'Standard security measures apply',
                    'Regular monitoring sufficient'
                ]
            }
        }
        
        rec = recommendations.get(risk_level, recommendations['MEDIUM'])
        rec['fraud_score'] = fraud_score
        
        return rec
    
    def print_analysis_report(self, analysis_result):
        """
        Print formatted analysis report
        """
        
        print(f"\n{'='*60}")
        print(" 📧 Email Fraud Analysis Report")
        print(f"{'='*60}\n")
        
        print(f"Email: {analysis_result['email']}")
        print(f"Username: {analysis_result['username']}")
        print(f"Domain: {analysis_result['domain']}")
        
        print(f"\n{'─'*60}")
        print("FRAUD ASSESSMENT:")
        print(f"{'─'*60}")
        
        risk_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }
        
        icon = risk_icons.get(analysis_result['risk_level'], '⚪')
        print(f"{icon} Risk Level: {analysis_result['risk_level']}")
        print(f"   Fraud Score: {analysis_result['fraud_score']}/100")
        
        # Print findings
        if analysis_result['findings']:
            print(f"\n{'─'*60}")
            print("FINDINGS:")
            print(f"{'─'*60}\n")
            
            for i, finding in enumerate(analysis_result['findings'], 1):
                severity_icon = risk_icons.get(finding['severity'], '⚪')
                print(f"{severity_icon} [{finding['severity']}] {finding['title']}")
                print(f"   Category: {finding['category']}")
                print(f"   {finding['description']}")
                print(f"   Impact: {finding['impact']}")
                if 'confidence' in finding:
                    print(f"   Confidence: {finding['confidence']}%")
                print()
        else:
            print(f"\n✓ No fraud indicators detected\n")
        
        # Print recommendation
        rec = analysis_result['recommendation']
        print(f"{'─'*60}")
        print("RECOMMENDATION:")
        print(f"{'─'*60}")
        print(f"Action: {rec['action']}")
        print(f"{rec['description']}\n")
        
        if rec['details']:
            print("Details:")
            for detail in rec['details']:
                print(f"  • {detail}")
        
        print(f"\n{'='*60}\n")


# Example usage and testing
if __name__ == "__main__":
    
    detector = EmailFraudDetector()
    
    print("="*60)
    print(" EMAIL FRAUD DETECTOR - TEST SUITE")
    print("="*60)
    
    # Test cases
    test_emails = [
        # Legitimate emails
        ("john.smith@gmail.com", "Legitimate - Gmail"),
        ("sarah.jones@outlook.com", "Legitimate - Outlook"),
        ("business@company.com", "Legitimate - Business"),
        
        # Disposable emails
        ("yayih16339@duoley.com", "Disposable - Your example"),
        ("test@tempmail.com", "Disposable - TempMail"),
        ("random123@guerrillamail.com", "Disposable - Guerrilla"),
        
        # Suspicious patterns
        ("abc12345@unknown.xyz", "Suspicious - Random pattern"),
        ("123456789@test.com", "Suspicious - All numbers"),
        ("randomuser9876@gmail.com", "Mixed - Random username, trusted domain")
    ]
    
    print("\nRunning tests on sample emails...\n")
    
    for email, description in test_emails:
        print(f"\n{'─'*60}")
        print(f"TEST: {description}")
        print(f"{'─'*60}")
        
        result = detector.analyze_email(email)
        
        # Print summary
        risk_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
        icon = risk_icons.get(result['risk_level'], '⚪')
        
        print(f"Email: {email}")
        print(f"{icon} Risk: {result['risk_level']} (Score: {result['fraud_score']}/100)")
        print(f"Recommendation: {result['recommendation']['action']}")
        print(f"Findings: {len(result['findings'])}")
    
    # Detailed analysis of the problematic email
    print("\n\n" + "="*60)
    print(" DETAILED ANALYSIS: yayih16339@duoley.com")
    print("="*60)
    
    detailed_result = detector.analyze_email("yayih16339@duoley.com")
    detector.print_analysis_report(detailed_result)
    
    print("\n✅ Email fraud detector testing complete!")
    print("   Ready for integration into main OSINT tool.\n")
