from typing import Dict
from datetime import datetime

class MetadataAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.suspicious_hours = config['metadata_analysis']['suspicious_hours']
        self.commonly_spoofed = ['paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix', 'irs', 'fedex', 'dhl']

    def analyze(self, metadata: Dict) -> Dict:
        if not metadata:
            return {'score': 50.0, 'confidence': 0.0, 'details': {'error': 'No metadata provided'}}

        features = {
            'sender_score': self._analyze_sender(metadata),
            'authentication_score': self._check_authentication(metadata),
            'timing_score': self._analyze_timing(metadata),
            'header_score': self._analyze_headers(metadata),
            'subject_score': self._analyze_subject(metadata),
            'routing_score': self._analyze_routing(metadata)
        }
        final_score = self._calculate_metadata_score(features)
        confidence = self._calculate_metadata_confidence(features, metadata)
        return {
            'score': round(final_score, 2),
            'confidence': round(confidence, 2),
            'details': {
                'features': features,
                'flags': self._generate_flags(features, metadata)
            }
        }

    def _analyze_sender(self, m: Dict) -> float:
        score = 0.0
        sender_email = (m.get('from') or '').lower()
        reply_to = (m.get('reply_to') or '').lower()
        return_path = (m.get('return_path') or '').lower()
        if not sender_email:
            return 50.0
        if reply_to and reply_to != sender_email:
            score += 30
        if return_path and return_path != sender_email:
            score += 25
        try:
            sender_domain = sender_email.split('@')[1]
            for brand in self.commonly_spoofed:
                if brand in sender_domain and sender_domain != f"{brand}.com":
                    score += 40
                    break
            free_providers = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com']
            if any(p in sender_domain for p in free_providers):
                local = sender_email.split('@')[0]
                corporate_keywords = ['admin','support','security','noreply','info']
                if any(k in local for k in corporate_keywords):
                    score += 20
        except Exception:
            score += 50
        return min(score, 100.0)

    def _check_authentication(self, m: Dict) -> float:
        score = 0.0
        spf = (m.get('received_spf') or '').lower()
        dkim = (m.get('dkim') or '').lower()
        dmarc = (m.get('dmarc') or '').lower()
        if spf in ['fail','softfail']:
            score += 35
        elif spf in ['none','neutral']:
            score += 20
        if dkim == 'fail':
            score += 35
        elif dkim in ['none','']:
            score += 15
        if dmarc == 'fail':
            score += 30
        elif dmarc in ['none','']:
            score += 10
        return min(score, 100.0)

    def _analyze_timing(self, m: Dict) -> float:
        score = 0.0
        ts = m.get('timestamp')
        if not ts:
            return 0.0
        try:
            if isinstance(ts, str):
                timestamp = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            else:
                timestamp = ts
            hour = timestamp.hour
            s = self.suspicious_hours['start']
            e = self.suspicious_hours['end']
            if s <= e:
                if s <= hour <= e:
                    score += 30
            else:
                if hour >= s or hour <= e:
                    score += 30
            if timestamp.weekday() >= 5:
                score += 15
        except Exception:
            score += 10
        return min(score, 100.0)

    def _analyze_headers(self, m: Dict) -> float:
        headers = m.get('headers', {})
        if not headers:
            return 20.0
        standard = ['Message-ID','Date','From','To']
        missing = [h for h in standard if h not in headers]
        score = (len(missing) ** 1.5) * 1.5
        return min(score, 100.0)

    def _analyze_subject(self, m: Dict) -> float:
        subject = (m.get('subject') or '')
        if not subject: return 10.0
        score = 0.0
        if subject.count('!') >= 2 or subject.count('?') >= 2:
            score += 25
        if subject.isupper() and len(subject) > 10:
            score += 30
        patterns = [r'\bverify\b.*\baccount\b', r'\bsuspended\b', r'\burgent\b.*\baction\b']
        lower = subject.lower()
        import re
        for p in patterns:
            if re.search(p, lower):
                score += 20
        return min(score, 100.0)

    def _analyze_routing(self, m: Dict) -> float:
        hops = m.get('relay_hops', 0)
        score = 0.0
        if hops >= 8:
            score += 40
        elif hops >= 5:
            score += 25
        elif hops == 0:
            score += 15
        return min(score, 100.0)

    def _calculate_metadata_score(self, features: Dict) -> float:
        weights = {
            'sender_score': 0.25,
            'authentication_score': 0.30,
            'timing_score': 0.10,
            'header_score': 0.15,
            'subject_score': 0.15,
            'routing_score': 0.05
        }
        total = 0.0
        for k,w in weights.items():
            total += features.get(k,0.0) * w
        return min(total, 100.0)

    def _calculate_metadata_confidence(self, features: Dict, metadata: Dict) -> float:
        completeness = 0
        required = ['from', 'subject', 'timestamp']
        for f in required:
            if metadata.get(f):
                completeness += 33
        if metadata.get('received_spf') or metadata.get('dkim'):
            completeness += 33
        return min(completeness, 100.0)

    def _generate_flags(self, features: Dict, metadata: Dict) -> list[str]:
        flags = []
        if features['sender_score'] >= 50:
            flags.append("📧 Suspicious sender information")
        if features['authentication_score'] >= 50:
            flags.append("🔒 Email authentication failures (SPF/DKIM/DMARC)")
        if features['timing_score'] >= 40:
            flags.append("⏰ Suspicious send time")
        if features['subject_score'] >= 50:
            flags.append("📝 Suspicious subject line")
        return flags or ["✓ No major metadata threats detected"]
