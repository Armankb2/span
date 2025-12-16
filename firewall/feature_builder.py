# ml/feature_builder.py
from typing import Dict, List, TYPE_CHECKING
import re
from urllib.parse import urlparse

if TYPE_CHECKING:
    import numpy as np
else:
    try:
        import numpy as np
        NUMPY_AVAILABLE = True
    except ImportError:
        NUMPY_AVAILABLE = False
        # Create a dummy numpy-like array class for fallback
        class DummyArray:
            def __init__(self, data, dtype=None):
                self.data = list(data) if not isinstance(data, list) else data
                self.dtype = dtype
            def reshape(self, *args):
                return self
        class DummyNP:
            array = lambda x, dtype=None: DummyArray(x, dtype)
            zeros = lambda x, dtype=None: DummyArray([0]*x[0] if isinstance(x, tuple) else [0]*x, dtype)
            class ndarray:
                pass
        np = DummyNP()

URL_REGEX = re.compile(r'http[s]?://[^\s"]+')

def extract_urls(text: str, provided_urls: List[str] = None) -> List[str]:
    urls = provided_urls or URL_REGEX.findall(text or "")
    return urls

def url_numeric_features(urls: List[str], suspicious_tlds: List[str], shorteners: List[str], trusted: List[str]) -> np.ndarray:
    """
    Returns a 1-D numpy array of numeric URL features:
    [url_count, high_risk_tld_count, shortener_count, ip_count, long_domain_count]
    """
    url_count = len(urls)
    high_tld = 0
    shortener = 0
    ip_count = 0
    long_domain = 0
    for u in urls:
        try:
            p = urlparse(u)
            domain = p.netloc.split(':')[0].lower()
            parts = domain.split('.')
            tld = '.' + parts[-1] if len(parts) > 1 else ''
            if tld in suspicious_tlds:
                high_tld += 1
            if any(s in domain for s in shorteners):
                shortener += 1
            if _is_ip(domain):
                ip_count += 1
            if len(domain) >= 40:
                long_domain += 1
        except Exception:
            continue
    return np.array([url_count, high_tld, shortener, ip_count, long_domain], dtype=float)

def text_numeric_features(text: str) -> np.ndarray:
    """
    Returns numeric textual features:
    [length, link_presence (0/1), exclamation_count, question_count, uppercase_ratio]
    """
    if not text:
        return np.zeros(5, dtype=float)
    l = len(text)
    link_presence = 1.0 if ('http://' in text.lower() or 'https://' in text.lower()) else 0.0
    exclaim = text.count('!')
    q = text.count('?')
    words = text.split()
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 1)
    uppercase_ratio = (caps_words / len(words)) if words else 0.0
    return np.array([l, link_presence, exclaim, q, uppercase_ratio], dtype=float)

def metadata_numeric_features(metadata: Dict) -> np.ndarray:
    """
    Returns metadata numeric features:
    [spf_flag, dkim_flag, dmarc_flag, relay_hops, timestamp_hour, subject_exclaim]
    where _flag values: pass=0, none/neutral=0.5, fail=1
    """
    def flag_score(v):
        if not v:
            return 0.5
        v = str(v).lower()
        if v in ('pass', 'pass\n'): return 0.0
        if v in ('fail', 'softfail'): return 1.0
        return 0.5

    spf = flag_score(metadata.get('received_spf'))
    dkim = flag_score(metadata.get('dkim'))
    dmarc = flag_score(metadata.get('dmarc'))

    relay = float(metadata.get('relay_hops', 0))
    # hour from timestamp if available
    hour = -1.0
    ts = metadata.get('timestamp')
    if ts:
        try:
            from datetime import datetime
            if isinstance(ts, str):
                dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
            else:
                dt = ts
            hour = float(dt.hour)
        except Exception:
            hour = -1.0

    subject = metadata.get('subject', '') or ''
    subject_exclaim = float(subject.count('!'))
    return np.array([spf, dkim, dmarc, relay, hour, subject_exclaim], dtype=float)

def _is_ip(s: str) -> bool:
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except:
        return False
