"""
Main OSINT Security Assessment Tool - COMPLETE WITH EMAIL FRAUD DETECTION
"""

import argparse
import sys
from data_collectors import OSINTCollector
from risk_assessor import RiskAssessor
from correlation_engine import CorrelationEngine
from threat_scorer import ThreatScorer
from executive_summary import ExecutiveSummaryGenerator
from email_fraud_detector import EmailFraudDetector  # NEW!

def get_interactive_input():
    """Get target and type from user interactively with menu"""
    
    print("\n" + "="*60)
    print(" 🔍 OSINT Security Assessment Tool - Enhanced")
    print("="*60)
    print("\n What would you like to scan?\n")
    print(" 1. Domain (e.g., example.com, google.com)")
    print(" 2. Email (e.g., test@example.com)")
    print(" 3. Exit")
    print("\n" + "="*60)
    
    choice = input("\n Enter choice (1-3): ").strip()
    
    if choice == '3':
        print("\n👋 Goodbye!")
        sys.exit(0)
    elif choice == '1':
        target_type = 'domain'
        target = input("\n Enter domain name: ").strip()
    elif choice == '2':
        target_type = 'email'
        target = input("\n Enter email address: ").strip()
    else:
        print("\n❌ Invalid choice")
        sys.exit(1)
    
    if not target:
        print("❌ Error: Target cannot be empty")
        sys.exit(1)
    
    # Confirm
    print(f"\n✓ Target: {target}")
    print(f"✓ Type: {target_type}")
    confirm = input("\n Start scan? (y/n): ").strip().lower()
    
    if confirm not in ['y', 'yes', '']:
        print("❌ Scan cancelled")
        sys.exit(0)
    
    return target, target_type

def main():
    """Main function - runs the complete OSINT assessment"""
    
    parser = argparse.ArgumentParser(
        description='OSINT Security Assessment Tool - Enhanced Version with Email Fraud Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:
    python3 osint_tool.py
  
  Command-line mode:
    python3 osint_tool.py example.com
    python3 osint_tool.py test@example.com --type email
        """
    )
    
    parser.add_argument('target', 
                       nargs='?',
                       help='Domain name or email address to analyze')
    
    parser.add_argument('--type', 
                       choices=['domain', 'email'], 
                       default=None,
                       help='Type of target (auto-detected if not specified)')
    
    args = parser.parse_args()
    
    # Determine mode
    if args.target:
        target = args.target
        if args.type:
            target_type = args.type
        else:
            target_type = 'email' if '@' in target else 'domain'
    else:
        target, target_type = get_interactive_input()
    
    # Print header
    print("\n" + "="*60)
    print(" 🔍 OSINT Security Assessment Tool - Enhanced")
    print("="*60)
    print(f" Target: {target}")
    print(f" Type: {target_type}")
    print("="*60)
    
    try:
        # API keys (optional)
        SHODAN_KEY = None
        VT_KEY = None
        
        # Step 1: Collect OSINT data
        total_steps = 6 if target_type == 'email' else 5
        
        print(f"\n[Step 1/{total_steps}] 🔎 Collecting data from multiple sources...")
        collector = OSINTCollector(
            shodan_api_key=SHODAN_KEY,
            virustotal_api_key=VT_KEY
        )
        osint_data = collector.collect_all(target, target_type)
        
        # Email Fraud Detection (for emails only)
        fraud_analysis = None
        if target_type == 'email':
            print(f"\n[Step 2/{total_steps}] 🚨 Email Fraud Detection...")
            fraud_detector = EmailFraudDetector()
            fraud_analysis = fraud_detector.analyze_email(target, osint_data)
            fraud_detector.print_analysis_report(fraud_analysis)
            
            current_step = 3
        else:
            current_step = 2
        
        # Step 2/3: Risk Assessment
        print(f"\n[Step {current_step}/{total_steps}] ⚠️  Analyzing security risks...")
        assessor = RiskAssessor()
        risk_report = assessor.assess_all(osint_data)
        current_step += 1
        
        # Step 3/4: Correlation Analysis
        print(f"\n[Step {current_step}/{total_steps}] 🧠 Performing intelligent correlation analysis...")
        correlation_engine = CorrelationEngine()
        correlation_report = correlation_engine.analyze(osint_data, risk_report)
        current_step += 1
        
        # Step 4/5: Threat Scoring
        print(f"\n[Step {current_step}/{total_steps}] 📊 Calculating precise threat scores...")
        threat_scorer = ThreatScorer()
        threat_scores = threat_scorer.score_all_findings(osint_data, correlation_report)
        current_step += 1
        
        # Step 5/6: Executive Summary
        print(f"\n[Step {current_step}/{total_steps}] 📋 Generating executive summary...")
        exec_summary_gen = ExecutiveSummaryGenerator()
        exec_summary = exec_summary_gen.generate(osint_data, risk_report, correlation_report)
        
        # Final summary
        print("\n" + "="*60)
        print(" ✅ COMPREHENSIVE ASSESSMENT COMPLETE")
        print("="*60)
        print(f" Overall Risk: {risk_report['overall_risk']}")
        
        # Email-specific output
        if fraud_analysis:
            print(f" Email Fraud Score: {fraud_analysis['fraud_score']}/100")
            print(f" Email Risk Level: {fraud_analysis['risk_level']}")
            print(f" Recommendation: {fraud_analysis['recommendation']['action']}")
        
        print(f" Threat Score: {threat_scores['aggregate']['overall_score']}/10.0")
        print(f" Risk Findings: {risk_report['summary']['total_findings']}")
        print(f" Correlations: {correlation_report['correlations_found']}")
        print(f" Attack Surface: {correlation_report['attack_surface_score']}/100")
        print(f" Data Sources: {len(osint_data.get('sources_used', []))}")
        print("="*60)
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠ Assessment cancelled by user")
        return 1
        
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        print("Please check your target and try again.")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
