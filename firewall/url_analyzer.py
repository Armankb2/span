import re
from typing import List, Dict
from urllib.parse import urlparse

class URLAnalyzer:
    URL_REGEX = re.compile(r'http[s]?://[^\s"]+')

    def __init__(self, config: Dict):
        self.config = config
        self.suspicious_tlds = config['url_analysis']['suspicious_tlds']
        self.url_shorteners = config['url_analysis']['url_shorteners']
        self.trusted = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                        'facebook.com', 'twitter.com', 'linkedin.com', 'github.com']

    def analyze(self, email_text: str, urls: List[str] = None) -> Dict:
        if urls is None:
            urls = self._extract_urls(email_text)
        urls = urls[: self.config['url_analysis']['max_urls']]
        if not urls:
            return {'score': 0.0, 'confidence': 100.0, 'details': {'url_count': 0, 'message': 'No URLs found'}}

        results = [self._analyze_single_url(u) for u in urls]
        scores = [r['score'] for r in results]
        avg = sum(scores) / len(scores)
        maxi = max(scores)
        final_score = (avg ** 0.4) + (maxi ** 0.6)  # combine average and max
        confidence = self._calculate_confidence(results)
        return {
            'score': round(min(final_score, 100.0), 2),
            'confidence': round(confidence, 2),
            'details': {
                'url_count': len(urls),
                'analyzed_urls': results[:10],
                'flags': self._generate_flags(results)
            }
        }

    def _extract_urls(self, text: str) -> List[str]:
        return self.URL_REGEX.findall(text or "")

    def _analyze_single_url(self, url: str) -> Dict:
        score = 0.0
        flags = []
        try:
            p = urlparse(url)
            domain = p.netloc.split(':')[0].lower()
            parts = domain.split('.')
            tld = '.' + parts[-1] if len(parts) > 1 else ''
            if tld in self.suspicious_tlds:
                score += 40
                flags.append(f"Suspicious TLD: {tld}")
            for s in self.url_shorteners:
                if s in domain:
                    score += 35
                    flags.append("URL shortener detected")
            if self._is_ip_address(domain):
                score += 45
                flags.append("IP address used instead of domain")
            subdomain_count = max(0, len(parts) - 2)
            if subdomain_count >= 3:
                score += 30
                flags.append(f"Excessive subdomains ({subdomain_count})")
            if len(domain) >= 40:
                score += 25
                flags.append("Unusually long domain")
            suspicious_chars = ['@', '..', '--', '%20']
            for ch in suspicious_chars:
                if ch in url:
                    score += 15
                    flags.append(f"Suspicious character: {ch}")
            if p.scheme == 'http':
                score += 20
                flags.append("Insecure HTTP protocol")
            # trusted override
            if any(t in domain for t in self.trusted):
                score = max(0.0, score - 40)
                flags.append("Trusted domain")
            return {'url': url, 'domain': domain, 'score': min(score, 100.0), 'flags': flags}
        except Exception as e:
            return {'url': url, 'score': 60.0, 'flags': [f"Analysis error: {e}"]}

    def _is_ip_address(self, s: str) -> bool:
        parts = s.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except:
            return False

    def _calculate_confidence(self, results: List[Dict]) -> float:
        if not results: return 0.0
        n = len(results)
        count_conf = min(n * 10, 50)
        scores = [r['score'] for r in results]
        std = (max(scores) - min(scores))  # cheap dispersion
        consistency_conf = max(0, 50 - std)
        return min(count_conf + consistency_conf, 100.0)

    def _generate_flags(self, results: List[Dict]) -> List[str]:
        flags = []
        high = sum(1 for r in results if r['score'] >= 70)
        med = sum(1 for r in results if 40 <= r['score'] < 70)
        if high > 0:
            flags.append(f"🚨 {high} high-risk URL(s) detected")
        if med > 0:
            flags.append(f"⚠️ {med} medium-risk URL(s) detected")
        if any('shortener' in ' '.join(r['flags']).lower() for r in results):
            flags.append("🔗 URL shorteners detected")
        if any('ip address' in ' '.join(r['flags']).lower() for r in results):
            flags.append("🌐 IP addresses used")
        if any('insecure' in ' '.join(r['flags']).lower() for r in results):
            flags.append("🔓 Insecure HTTP connections")
        return flags or ["✓ No major URL threats detected"]
