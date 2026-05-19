"""
Threat Intelligence Scoring System
Quantifies security risks using CVSS-inspired methodology
"""

class ThreatScorer:
    """Calculate precise threat scores (0-10) for findings"""
    
    def __init__(self):
        self.scores = {}
    
    def score_all_findings(self, osint_data, correlations):
        """Score all findings and correlations"""
        
        print(f"\n{'='*60}")
        print(" 📊 Calculating Threat Scores")
        print(f"{'='*60}\n")
        
        scored_items = []
        
        # Score correlations (if any exist)
        for corr in correlations.get('correlations', []):
            score = self.calculate_correlation_score(corr, osint_data)
            scored_items.append({
                'item': corr['pattern'],
                'type': 'Correlation',
                'score': score,
                'severity': corr['severity']
            })
            
            print(f"  • {corr['pattern']}: {score}/10.0 [{corr['severity']}]")
        
        # Calculate aggregate scores
        aggregate = self.calculate_aggregate_scores(scored_items, osint_data)
        
        # Print summary
        if scored_items:
            print(f"\n{'─'*60}")
            print(f"📈 Aggregate Threat Score: {aggregate['overall_score']}/10.0")
            print(f"   Risk Level: {aggregate['risk_level']}")
            print(f"{'='*60}\n")
        else:
            print(f"  ℹ️  No critical correlations to score")
            print(f"  ✓ Attack Surface Score: {correlations.get('attack_surface_score', 0)}/100")
            print(f"{'='*60}\n")
        
        return {
            'individual_scores': scored_items,
            'aggregate': aggregate
        }
    
    def calculate_correlation_score(self, correlation, context):
        """Calculate threat score (0-10) for a correlation"""
        
        # Base components
        exploitability = self.calculate_exploitability(correlation)
        impact = self.calculate_impact(correlation)
        
        # Base score
        base_score = (impact * exploitability) / 10.0
        
        # Modifiers
        exploit_maturity = self.assess_exploit_maturity(correlation)
        exposure_level = self.assess_exposure(correlation)
        
        # Final score
        final_score = base_score * exploit_maturity * exposure_level
        
        return round(min(final_score, 10.0), 1)
    
    def calculate_exploitability(self, correlation):
        """How easy to exploit? (0-10)"""
        
        score = 0.0
        pattern = correlation.get('pattern', '').lower()
        
        # Attack complexity
        if any(x in pattern for x in ['exposed', 'open', 'public']):
            score += 5.0  # Easy to exploit
        else:
            score += 3.0  # Moderate
        
        # Authentication required
        if 'admin' in pattern or 'database' in pattern:
            score += 3.0  # High value target
        else:
            score += 2.0
        
        return min(score, 10.0)
    
    def calculate_impact(self, correlation):
        """Impact if exploited? (0-10)"""
        
        score = 0.0
        pattern = correlation.get('pattern', '').lower()
        impact_text = correlation.get('business_impact', '').lower()
        
        # Data breach potential
        if 'data breach' in impact_text or 'database' in pattern:
            score += 4.0
        
        # System compromise
        if 'compromise' in impact_text or 'admin' in pattern:
            score += 4.0
        
        # Service disruption
        if 'disruption' in impact_text:
            score += 2.0
        
        # Default moderate impact
        if score == 0:
            score = 5.0
        
        return min(score, 10.0)
    
    def assess_exploit_maturity(self, correlation):
        """Exploits available? (0.7-1.0 multiplier)"""
        
        indicators = ' '.join(correlation.get('indicators', [])).lower()
        
        if 'cve' in indicators:
            return 1.0  # Known exploits
        elif 'outdated' in indicators or 'vulnerable' in indicators:
            return 0.9  # Likely exploitable
        else:
            return 0.8  # Theoretical
    
    def assess_exposure(self, correlation):
        """How exposed? (0.7-1.0 multiplier)"""
        
        severity = correlation.get('severity', 'LOW')
        
        exposure_map = {
            'CRITICAL': 1.0,
            'HIGH': 0.9,
            'MEDIUM': 0.8,
            'LOW': 0.7
        }
        
        return exposure_map.get(severity, 0.8)
    
    def calculate_aggregate_scores(self, scored_items, osint_data):
        """Calculate overall aggregate scores"""
        
        if not scored_items:
            # No correlations scored, return baseline
            return {
                'overall_score': 0.0,
                'risk_level': 'LOW',
                'highest_score': 0.0,
                'average_score': 0.0,
                'critical_count': 0
            }
        
        scores = [item['score'] for item in scored_items]
        
        # Calculate metrics
        highest = max(scores)
        average = sum(scores) / len(scores)
        
        # Critical findings (score >= 8.0)
        critical_scores = [s for s in scores if s >= 8.0]
        
        # Overall score calculation
        if critical_scores:
            overall = max(critical_scores)
        else:
            overall = average
        
        # Determine risk level
        if overall >= 9.0:
            risk_level = 'CRITICAL'
        elif overall >= 7.0:
            risk_level = 'HIGH'
        elif overall >= 4.0:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'overall_score': round(overall, 1),
            'risk_level': risk_level,
            'highest_score': round(highest, 1),
            'average_score': round(average, 1),
            'critical_count': len(critical_scores)
        }
