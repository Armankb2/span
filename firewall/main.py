import json
from firewall_engine import PhishingDefenseFirewall

def main():
    firewall = PhishingDefenseFirewall('config.yaml')
    with open('data/sample_emails.json', 'r') as f:
        emails = json.load(f)

    for i, email in enumerate(emails, 1):
        print("="*60)
        print(f"Email #{i}")
        res = firewall.analyze_email(email)
        print(f"Final score: {res['final_score']}/100  | Threat: {res['threat_level']} | Action: {res['action']}")
        print("Recommendation:", res['recommendation'])
        print("Flags:", ', '.join(res['all_flags'][:10]))
        print("Layer scores:", res['layer_scores'])
        print("="*60, "\n")

if __name__ == '__main__':
    main()
