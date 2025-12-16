# ml/predictor_cli.py
# ml/predictor_cli.py
import json
import sys
from pathlib import Path
import yaml

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from predictor import MLScorer

CONFIG_PATH = '../config.yaml'

def prompt_user_input():
    print("Paste the full email text (end with a blank line):")
    lines = []
    while True:
        line = input()
        if line.strip() == "" and lines:
            break
        lines.append(line)
    text = "\n".join(lines).strip()
    urls_input = input("Enter URLs found (comma separated) or leave blank: ").strip()
    urls = [u.strip() for u in urls_input.split(',')] if urls_input else []
    sender = input("From (sender email): ").strip()
    subject = input("Subject: ").strip()
    ts = input("Timestamp (YYYY-MM-DD HH:MM:SS) or leave blank: ").strip()
    metadata = {
        "from": sender,
        "subject": subject,
        "timestamp": ts or None,
        "received_spf": input("SPF (pass/fail/none): ").strip() or None,
        "dkim": input("DKIM (pass/fail/none): ").strip() or None,
        "dmarc": input("DMARC (pass/fail/none): ").strip() or None,
        "relay_hops": int(input("Relay hops (0 if unknown): ").strip() or 0)
    }
    return {"text": text, "urls": urls, "metadata": metadata}

def main():
    cfg = yaml.safe_load(open(CONFIG_PATH))
    scorer = MLScorer(config=cfg)
    if not scorer.available():
        print("ML model artifacts not found in ml/model_artifacts/. Please train the model first.")
        return

    email = prompt_user_input()
    ml_score = scorer.predict_score(email['text'], email['urls'], email['metadata'])
    print("\n=== ML Prediction ===")
    print(f"ML phishing probability score: {ml_score}/100.0")

    # Optionally run rule-based quick check using firewall_engine (if present)
    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from firewall_engine import PhishingDefenseFirewall
        fw = PhishingDefenseFirewall()
        # run analysis but it will attempt to use ML again; to show rule-based only:
        res = fw.analyze_email(email)
        print("\n=== Combined Firewall Result ===")
        print(f"Final score: {res['final_score']}/100 | Threat: {res['threat_level']} | Action: {res['action']}")
        print("Recommendation:", res['recommendation'])
        print("Flags:", ', '.join(res['all_flags'][:10]))
    except Exception as e:
        print("Rule-based firewall not available or import failed:", e)

if __name__ == '__main__':
    main()
