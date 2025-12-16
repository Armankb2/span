import re
from typing import Dict
from nltk.sentiment.vader import SentimentIntensityAnalyzer  # pyright: ignore[reportMissingImports]

class EmailTextAnalyzer:
    def __init__(self, config: Dict):
        self.config = config
        self.phishing_keywords = [k.lower() for k in config['email_analysis']['phishing_keywords']]
        self.sid = SentimentIntensityAnalyzer()
        # precompiled patterns
        self.patterns = {
            'urgent': re.compile(r'\b(urgent|immediate|asap|now|act now)\b', re.I),
            'financial': re.compile(r'\b(bank|credit|debit|payment|transaction|refund)\b', re.I),
            'credential': re.compile(r'\b(password|username|login|credential|account)\b', re.I),
            'threat': re.compile(r'\b(suspend|close|terminate|expire|block|restrict)\b', re.I),
            'reward': re.compile(r'\b(prize|winner|won|reward|gift|lottery)\b', re.I),
        }

    def analyze(self, email_text: str) -> Dict:
        if not email_text or len(email_text) < self.config['email_analysis']['min_length']:
            return {'score': 0, 'confidence': 0, 'details': {'error': 'Text too short'}}

        text = email_text[:self.config['email_analysis']['max_length']]
        features = {}
        features['keyword_score'] = self._check_phishing_keywords(text)
        features['pattern_score'] = self._check_patterns(text)
        features['urgency_score'] = self._analyze_urgency(text)
        features['sentiment_score'] = self._analyze_sentiment(text)
        features['linguistic_score'] = self._analyze_linguistic(text)
        features['structure_score'] = self._analyze_structure(text)

        final_score = self._calculate_final_score(features)
        confidence = self._calculate_confidence(features)

        return {
            'score': round(final_score, 2),
            'confidence': round(confidence, 2),
            'details': {
                'features': features,
                'flags': self._generate_flags(features, text)
            }
        }

    def _check_phishing_keywords(self, text: str) -> float:
        text_l = text.lower()
        matches = sum(1 for kw in self.phishing_keywords if kw in text_l)
        if matches >= 5:
            return 95.0
        if matches >= 3:
            return 75.0
        if matches >= 2:
            return 50.0
        if matches >= 1:
            return 30.0
        return 0.0

    def _check_patterns(self, text: str) -> float:
        score = 0.0
        weights = {'urgent': 15, 'threat': 20, 'credential': 25, 'financial': 20, 'reward': 15}
        for name, pat in self.patterns.items():
            matches = len(pat.findall(text))
            if matches:
                score += min(matches * weights.get(name, 10), 100)
        return min(score, 100.0)

    def _analyze_urgency(self, text: str) -> float:
        urgent_words = ['immediately', 'urgent', 'asap', 'now', 'act now', 'limited time', 'deadline']
        count = sum(1 for w in urgent_words if w in text.lower())
        if count >= 4: return 90.0
        if count >= 2: return 60.0
        if count >= 1: return 30.0
        return 0.0

    def _analyze_sentiment(self, text: str) -> float:
        scores = self.sid.polarity_scores(text)
        # we consider very negative/very positive (extreme) as suspicious
        extreme = max(abs(scores['neg']), abs(scores['pos']))
        if extreme > 0.6: return 70.0
        if extreme > 0.3: return 40.0
        return 10.0

    def _analyze_linguistic(self, text: str) -> float:
        score = 0.0
        exclam = text.count('!')
        qmark = text.count('?')
        words = text.split()
        caps_words = sum(1 for w in words if w.isupper() and len(w) > 1)
        if exclam >= 3: score += 30
        if qmark >= 2: score += 20
        caps_ratio = caps_words / len(words) if words else 0
        if caps_ratio > 0.3: score += 40
        elif caps_ratio > 0.15: score += 25
        return min(score, 100.0)

    def _analyze_structure(self, text: str) -> float:
        score = 0.0
        if ('http://' in text.lower() or 'https://' in text.lower()) and len(text) < 100:
            score += 50
        link_count = text.lower().count('http://') + text.lower().count('https://')
        if link_count >= 5:
            score += 40
        elif link_count >= 3:
            score += 25
        greetings = ['dear', 'hello', 'hi', 'greetings']
        signatures = ['regards', 'sincerely', 'thanks', 'best']
        tl = text.lower()
        has_greeting = any(g in tl[:100] for g in greetings)
        has_signature = any(s in tl[-100:] for s in signatures)
        if has_greeting and not has_signature:
            score += 30
        return min(score, 100.0)

    def _calculate_final_score(self, features: dict) -> float:
        weights = {
            'keyword_score': 0.25,
            'pattern_score': 0.20,
            'urgency_score': 0.20,
            'sentiment_score': 0.10,
            'linguistic_score': 0.15,
            'structure_score': 0.10
        }
        total = 0.0
        for k, w in weights.items():
            total += (features.get(k, 0.0) * w)
        return min(total, 100.0)

    def _calculate_confidence(self, features: dict) -> float:
        vals = list(features.values())
        # simple spread-based confidence
        maxv, minv = max(vals), min(vals)
        spread = maxv - minv
        confidence = max(0, 100 - spread)
        return min(confidence, 100.0)

    def _generate_flags(self, features: dict, text: str):
        flags = []
        if features['keyword_score'] >= 50:
            flags.append("⚠️ Multiple phishing keywords detected")
        if features['urgency_score'] >= 60:
            flags.append("🚨 High urgency language detected")
        if features['pattern_score'] >= 60:
            flags.append("🔍 Suspicious patterns found")
        if features['linguistic_score'] >= 50:
            flags.append("📝 Linguistic anomalies detected")
        if features['structure_score'] >= 50:
            flags.append("📧 Suspicious email structure")
        if features['sentiment_score'] >= 60:
            flags.append("😨 Extreme sentiment detected")
        return flags or ["✓ No major text-based threats detected"]
