"""
Executive Summary Generator
Translates technical findings into business language
"""

class ExecutiveSummaryGenerator:
    """Generate executive-friendly security summaries"""
    
    def generate(self, osint_data, risk_report, correlations):
        """Create executive summary"""
        
        summary = {
            'headline': self.create_headline(risk_report, correlations),
            'key_findings': self.summarize_key_findings(correlations),
            'business_impact': self.assess_business_impact(correlations),
            'priority_actions': self.recommend_priority_actions(correlations),
            'metrics': self.generate_metrics(osint_data, risk_report, correlations)
        }
        
        self.print_executive_summary(summary)
        
        return summary
    
    def create_headline(self, risk_report, correlations):
        """Create one-line summary"""
        
        overall_risk = risk_report['overall_risk']
        corr_count = len(correlations.get('correlations', []))
        critical_count = len([c for c in correlations.get('correlations', []) if c['severity'] == 'CRITICAL'])
        
        if critical_count > 0:
            return f"CRITICAL: {critical_count} critical security issue(s) require immediate attention"
        elif overall_risk == 'HIGH':
            return f"HIGH RISK: {corr_count} security concern(s) identified across infrastructure"
        elif overall_risk == 'MEDIUM':
            return f"MODERATE RISK: Security improvements recommended across {corr_count} area(s)"
        else:
            return "LOW RISK: Security posture is generally sound with minor improvements suggested"
    
    def summarize_key_findings(self, correlations):
        """Top 3-5 findings in business terms"""
        
        findings = []
        
        for corr in correlations.get('correlations', [])[:5]:
            finding = {
                'issue': corr['pattern'],
                'risk': corr['severity'],
                'business_concern': corr['business_impact'],
                'action_needed': corr['remediation'][0] if corr['remediation'] else 'Review security controls'
            }
            findings.append(finding)
        
        return findings
    
    def assess_business_impact(self, correlations):
        """Translate to business impact"""
        
        impacts = {
            'financial': [],
            'reputational': [],
            'operational': [],
            'compliance': []
        }
        
        for corr in correlations.get('correlations', []):
            if 'data breach' in corr.get('business_impact', '').lower():
                impacts['financial'].append('Potential data breach fines (GDPR: up to 4% annual revenue)')
                impacts['reputational'].append('Customer trust loss from security incident')
            
            if 'database' in corr.get('pattern', '').lower():
                impacts['operational'].append('Potential service disruption if database compromised')
            
            if any(x in corr.get('business_impact', '').lower() for x in ['gdpr', 'compliance', 'regulatory']):
                impacts['compliance'].append('Regulatory compliance violations possible')
        
        return impacts
    
    def recommend_priority_actions(self, correlations):
        """Top 3 priority actions for executives"""
        
        actions = []
        
        # Get all remediation actions
        all_actions = []
        for corr in correlations.get('correlations', []):
            if corr['severity'] in ['CRITICAL', 'HIGH']:
                all_actions.extend(corr['remediation'][:2])
        
        # Deduplicate and prioritize
        unique_actions = list(dict.fromkeys(all_actions))[:3]
        
        return unique_actions or ['Conduct comprehensive security audit', 'Review access controls', 'Update security policies']
    
    def generate_metrics(self, osint_data, risk_report, correlations):
        """Key metrics for dashboard"""
        
        return {
            'overall_risk_score': self.risk_to_score(risk_report['overall_risk']),
            'attack_surface_score': correlations.get('attack_surface_score', 0),
            'critical_issues': len([c for c in correlations.get('correlations', []) if c['severity'] == 'CRITICAL']),
            'high_issues': len([c for c in correlations.get('correlations', []) if c['severity'] == 'HIGH']),
            'data_sources_analyzed': len(osint_data.get('sources_used', [])),
            'findings_total': risk_report['summary']['total_findings']
        }
    
    def risk_to_score(self, risk_level):
        """Convert risk level to 0-100 score"""
        mapping = {'LOW': 25, 'MEDIUM': 55, 'HIGH': 80, 'CRITICAL': 95}
        return mapping.get(risk_level, 50)
    
    def print_executive_summary(self, summary):
        """Print formatted executive summary"""
        
        print(f"\n{'='*60}")
        print(" 📋 EXECUTIVE SUMMARY")
        print(f"{'='*60}\n")
        
        print(f"🎯 {summary['headline']}\n")
        
        print(f"{'─'*60}")
        print("KEY METRICS:")
        print(f"{'─'*60}")
        metrics = summary['metrics']
        print(f"  Overall Risk Score: {metrics['overall_risk_score']}/100")
        print(f"  Attack Surface: {metrics['attack_surface_score']}/100")
        print(f"  Critical Issues: {metrics['critical_issues']}")
        print(f"  High Priority Issues: {metrics['high_issues']}")
        print(f"  Data Sources Analyzed: {metrics['data_sources_analyzed']}")
        
        if summary['key_findings']:
            print(f"\n{'─'*60}")
            print("TOP SECURITY CONCERNS:")
            print(f"{'─'*60}")
            for i, finding in enumerate(summary['key_findings'][:3], 1):
                print(f"\n{i}. {finding['issue']} [{finding['risk']}]")
                print(f"   Business Impact: {finding['business_concern']}")
                print(f"   Immediate Action: {finding['action_needed']}")
        
        if summary['priority_actions']:
            print(f"\n{'─'*60}")
            print("RECOMMENDED PRIORITY ACTIONS:")
            print(f"{'─'*60}")
            for i, action in enumerate(summary['priority_actions'], 1):
                print(f"{i}. {action}")
        
        print(f"\n{'='*60}\n")
