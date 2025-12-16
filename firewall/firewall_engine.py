# firewall_engine.py
# UPDATED FINAL VERSION – PROPER LEVEL SEPARATION

# --------------------------------
# RULE-BASED ANALYZERS
# --------------------------------

class EmailTextAnalyzer:
    def analyze(self, text):
        score = 0
        flags = []
        t = text.lower()

        if "urgent" in t:
            score += 30
            flags.append("Urgent language detected")

        if "verify" in t or "confirm" in t:
            score += 25
            flags.append("Credential verification request")

        if "account" in t:
            score += 15
            flags.append("Account-related content")

        if "click" in t or "link" in t:
            score += 10
            flags.append("Click action requested")

        return {"score": min(score, 100), "flags": flags}


class URLAnalyzer:
    def analyze(self, text, urls):
        score = 0
        flags = []

        suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz"]

        for url in urls:
            if url.startswith("http://"):
                score += 25
                flags.append("Insecure HTTP link")

            for tld in suspicious_tlds:
                if tld in url:
                    score += 35
                    flags.append(f"Suspicious TLD detected ({tld})")

        return {"score": min(score, 100), "flags": flags}


class MetadataAnalyzer:
    def analyze(self, metadata):
        score = 0
        flags = []

        if metadata.get("received_spf") != "pass":
            score += 30
            flags.append("SPF authentication failed")

        if metadata.get("dkim") != "pass":
            score += 25
            flags.append("DKIM authentication failed")

        if metadata.get("dmarc") != "pass":
            score += 25
            flags.append("DMARC authentication failed")

        if metadata.get("relay_hops", 0) > 5:
            score += 15
            flags.append("High relay hops detected")

        return {"score": min(score, 100), "flags": flags}


# --------------------------------
# ML SCORER (BOOSTED BUT CONTROLLED)
# --------------------------------

class MLWrapper:
    def __init__(self):
        try:
            from ml.predictor import MLScorer
            self.model = MLScorer()
        except Exception:
            self.model = None

    def predict(self, text, urls, metadata):
        if not self.model:
            return 0
        try:
            # ML score already scaled 0–100
            return int(self.model.predict_score(text, urls, metadata))
        except Exception:
            return 0


# --------------------------------
# MAIN FIREWALL ENGINE
# --------------------------------

class PhishingDefenseFirewall:
    def __init__(self):
        self.text_analyzer = EmailTextAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.metadata_analyzer = MetadataAnalyzer()
        self.ml = MLWrapper()

    def analyze_email(self, email_data):

        text = email_data.get("text", "")
        urls = email_data.get("urls", [])
        metadata = email_data.get("metadata", {})

        # ----------------------------
        # RULE-BASED ANALYSIS
        # ----------------------------
        text_res = self.text_analyzer.analyze(text)
        url_res = self.url_analyzer.analyze(text, urls)
        meta_res = self.metadata_analyzer.analyze(metadata)

        text_score = text_res["score"]
        url_score = url_res["score"]
        meta_score = meta_res["score"]

        # ----------------------------
        # ML ANALYSIS
        # ----------------------------
        ml_score = self.ml.predict(text, urls, metadata)

        # ----------------------------
        # WEIGHTED BASE SCORE
        # ----------------------------
        final_score = int(
            text_score * 0.25 +
            url_score * 0.25 +
            meta_score * 0.25 +
            ml_score * 0.25
        )

        # ----------------------------
        # 🔥 REFINED ESCALATION RULE
        # ----------------------------
        # Only escalate to HIGH if VERY STRONG phishing is present
        auth_fail = meta_score >= 70
        strong_phishing = (text_score >= 60 and url_score >= 50)

        if auth_fail and strong_phishing:
            final_score = max(final_score, 85)

        # ----------------------------
        # DECISION LOGIC
        # ----------------------------
        if final_score >= 70:
            threat = "HIGH"
            action = "BLOCK"
            recommendation = "Phishing detected. Do NOT interact."
        elif final_score >= 40:
            threat = "MEDIUM"
            action = "QUARANTINE"
            recommendation = "Suspicious email. Verify sender."
        else:
            threat = "LOW"
            action = "ALLOW"
            recommendation = "Email appears safe."

        # ----------------------------
        # RESPONSE
        # ----------------------------
        return {
            "final_score": final_score,
            "threat_level": threat,
            "action": action,
            "recommendation": recommendation,
            "confidence": final_score,
            "layer_scores": {
                "email_text": text_res,
                "url_analysis": url_res,
                "metadata": meta_res,
                "ml": ml_score
            },
            "all_flags": (
                text_res["flags"]
                + url_res["flags"]
                + meta_res["flags"]
            )
        }
