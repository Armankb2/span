# ml/generate_dataset.py
import os
import json
import random
import csv
from datetime import datetime, timedelta
from pathlib import Path

OUT_DIR = Path('data')
OUT_DIR.mkdir(parents=True, exist_ok=True)

PHISHING_TEMPLATES = [
    "URGENT: Your {brand} account has been suspended. Verify immediately: {url}",
    "Your payment could not be processed. Click {url} to update your billing info.",
    "Congratulations! You won a prize. Claim at {url}",
    "Security Alert: Unusual login activity detected. Confirm your identity: {url}",
    "You are eligible for a tax refund. Provide your details here: {url}"
]

LEGIT_TEMPLATES = [
    "Your {brand} monthly statement is ready. View it at {url}",
    "Delivery notification: Your package is out for delivery. Track: {url}",
    "Reminder: Your appointment with {org} is scheduled at {time}.",
    "Newsletter: Latest updates from {org} — read more at {url}",
    "Payment received: Thank you for your payment to {org}."
]

BRANDS = ['paypal', 'bankofamerica', 'amazon', 'google', 'microsoft', 'fedex', 'dhl', 'netflix', 'apple']
TLDS_PHISH = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
TLDS_LEGIT = ['.com', '.org', '.net', '.co', '.in']
SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'goo.gl']

def random_url(phishing=True):
    if phishing:
        # craft suspicious-looking domain or shortener
        if random.random() < 0.25:
            return f"http://{random.choice(SHORTENERS)}/{random.randrange(10000,99999)}"
        domain = f"{random.choice(BRANDS)}-secure{random.choice(TLDS_PHISH)}"
        path = f"/login/{random.randrange(1000,99999)}"
        return f"http://{domain}{path}"
    else:
        domain = f"www.{random.choice(BRANDS)}{random.choice(TLDS_LEGIT)}"
        path = f"/track/{random.randrange(1000,99999)}"
        return f"https://{domain}{path}"

def random_from(phishing=True):
    if phishing:
        # use suspicious domain
        domain = f"security@{random.choice(BRANDS)}-alert{random.choice(TLDS_PHISH)}"
    else:
        domain = f"noreply@{random.choice(BRANDS)}.com"
    return domain

def random_metadata(phishing=True, ts_base=None):
    if ts_base is None:
        ts_base = datetime(2025,1,1)
    # random timestamp within first 365 days
    ts = ts_base + timedelta(days=random.randint(0, 365), hours=random.randint(0,23), minutes=random.randint(0,59))
    if phishing:
        spf = random.choice(['fail','softfail','none','neutral'])
        dkim = random.choice(['fail','none',''])
        dmarc = random.choice(['fail','none',''])
        relay = random.randint(2, 10)
    else:
        spf = 'pass'
        dkim = 'pass'
        dmarc = 'pass'
        relay = random.randint(0, 3)
    subject = ""
    return {
        "from": random_from(phishing),
        "subject": subject,
        "timestamp": ts.strftime('%Y-%m-%d %H:%M:%S'),
        "received_spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "relay_hops": relay
    }

def generate_dataset(n_samples=20000, phishing_ratio=0.35, out_prefix='synthetic'):
    """
    Generate n_samples emails with phishing_ratio labeled as phishing (1).
    Saves 3 CSVs: <prefix>_train.csv, <prefix>_test.csv, <prefix>_holdout.csv
    Also saves combined JSON for convenience.
    """
    samples = []
    for i in range(n_samples):
        is_phish = random.random() < phishing_ratio
        if is_phish:
            template = random.choice(PHISHING_TEMPLATES)
        else:
            template = random.choice(LEGIT_TEMPLATES)
        url = random_url(phishing=is_phish)
        brand = random.choice(BRANDS)
        org = brand.capitalize()
        time_str = (datetime(2025,1,1) + timedelta(hours=random.randint(8,18))).strftime('%I:%M %p')
        text = template.format(brand=brand, url=url, org=org, time=time_str)
        metadata = random_metadata(phishing=is_phish)
        # set subject: for legit templates, fill; for phishing set stronger subject
        if is_phish:
            metadata['subject'] = f"URGENT: {brand.capitalize()} notice"
        else:
            metadata['subject'] = f"{org} notification"

        sample = {
            "text": text,
            "urls": [url],
            "metadata": metadata,
            "label": 1 if is_phish else 0
        }
        samples.append(sample)

    # shuffle and split
    random.shuffle(samples)
    n_train = int(0.7 * n_samples)
    n_test = int(0.2 * n_samples)
    train = samples[:n_train]
    test = samples[n_train:n_train+n_test]
    hold = samples[n_train+n_test:]

    def save_csv(list_samples, path):
        with open(path, 'w', newline='', encoding='utf8') as f:
            writer = csv.DictWriter(f, fieldnames=['text','urls','metadata','label'])
            writer.writeheader()
            for s in list_samples:
                writer.writerow({
                    'text': s['text'],
                    'urls': json.dumps(s['urls']),
                    'metadata': json.dumps(s['metadata']),
                    'label': s['label']
                })

    save_csv(train, OUT_DIR / f"{out_prefix}_train.csv")
    save_csv(test, OUT_DIR / f"{out_prefix}_test.csv")
    save_csv(hold, OUT_DIR / f"{out_prefix}_holdout.csv")

    # save combined json
    with open(OUT_DIR / f"{out_prefix}_all.json", 'w', encoding='utf8') as f:
        json.dump(samples, f, indent=2)

    print(f"Generated dataset: {len(samples)} samples")
    print(f"Train: {len(train)} saved to {OUT_DIR / (out_prefix + '_train.csv')}")
    print(f"Test:  {len(test)} saved to {OUT_DIR / (out_prefix + '_test.csv')}")
    print(f"Holdout: {len(hold)} saved to {OUT_DIR / (out_prefix + '_holdout.csv')}")
    return str(OUT_DIR / f"{out_prefix}_train.csv")
