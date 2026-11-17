"""
CyberGuard Desktop - URL Extraction & Static Heuristic Analyzer
Performs local, static analysis of URLs without network queries or external submissions.
"""

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Optional


@dataclass
class URLIndicator:
    name: str
    description: str
    score: float  # contribution to url risk


@dataclass
class URLAnalysisResult:
    url: str
    domain: str
    risk_score: float  # 0 to 100
    is_suspicious: bool
    indicators: List[URLIndicator]
    explanations: List[str]


class URLAnalyzer:
    """
    Extracts and evaluates URLs found in on-screen text using explainable static heuristics.
    Strictly local: performs zero DNS queries, zero HTTP requests, and zero external lookups.
    """

    def __init__(self):
        # Comprehensive URL regex
        self.url_regex = re.compile(
            r"""(?xi)
            \b
            (?:https?://|www\.)
            [^\s<>"'{}|\\^`\[\]]+
            """,
            re.IGNORECASE
        )

        # IP address URL regex (e.g. http://192.168.1.50/login)
        self.ip_regex = re.compile(r"^https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/.*)?$", re.IGNORECASE)

        # Well-known URL shorteners
        self.shorteners = {
            "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "buff.ly",
            "ow.ly", "cutt.ly", "tiny.cc", "rb.gy", "v.gd"
        }

        # Targeted brands often spoofed in phishing subdomains
        self.targeted_brands = {
            "paypal", "apple", "microsoft", "google", "netflix", "amazon",
            "chase", "wellsfargo", "bankofamerica", "citi", "barclays",
            "hdfc", "icici", "sbi", "facebook", "instagram", "whatsapp",
            "binance", "coinbase", "metamask", "steam"
        }

        # Suspicious suspicious top-level domains commonly abused in bulk campaigns
        self.suspicious_tlds = {
            "xyz", "top", "work", "loan", "click", "rest", "gq", "cf", "tk", "ml", "ga", "buzz", "cam", "fit"
        }

    def extract_urls(self, text: str) -> List[str]:
        """Extract all candidate URL strings from OCR text."""
        if not text:
            return []
        matches = self.url_regex.findall(text)
        cleaned = []
        for u in matches:
            # Strip trailing punctuation that OCR often glues to the URL
            u_clean = u.rstrip(".,;:!?)'\"")
            if len(u_clean) > 8:
                cleaned.append(u_clean)
        return list(dict.fromkeys(cleaned))  # Deduplicate preserving order

    def analyze_url(self, raw_url: str) -> URLAnalysisResult:
        """
        Analyzes a single URL statically against phishing and deception patterns.
        """
        url = raw_url
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url

        try:
            parsed = urllib.parse.urlparse(url)
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
        except Exception:
            return URLAnalysisResult(
                url=raw_url, domain="", risk_score=20.0, is_suspicious=False,
                indicators=[URLIndicator("Malformed URL", "Could not parse URL standard format", 20.0)],
                explanations=["URL is malformed or invalidly structured."]
            )

        # Extract domain without port
        domain = netloc.split(":")[0]
        indicators: List[URLIndicator] = []
        score = 0.0

        # 1. IP-address-based host (Major red flag for public web services)
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", domain):
            indicators.append(URLIndicator(
                "Direct IP Host",
                f"URL uses a raw IP address ({domain}) instead of a registered domain name.",
                75.0
            ))
            score += 75.0

        # 2. Punycode / Internationalized Domain Names (Homograph attack indicator)
        if "xn--" in domain:
            indicators.append(URLIndicator(
                "Punycode Domain",
                "Domain contains 'xn--' prefix indicating internationalized/homoglyph characters.",
                60.0
            ))
            score += 60.0

        # Check for mixed cyrillic/greek homoglyphs in raw text
        non_ascii_chars = [c for c in domain if ord(c) > 127]
        if non_ascii_chars:
            indicators.append(URLIndicator(
                "Homoglyph Character Risk",
                "Domain contains non-ASCII characters that may spoof latin letters.",
                60.0
            ))
            score += 60.0

        # 3. Misleading brand names in subdomains or paths
        # E.g. paypal.com.user-verify.net or update-chase.com
        domain_parts = domain.split(".")
        root_domain = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain

        for brand in self.targeted_brands:
            if brand in domain:
                # If brand is in the subdomain but NOT the root domain (e.g. paypal.com.auth-check.xyz)
                if brand in domain and brand not in root_domain:
                    indicators.append(URLIndicator(
                        "Brand Spoofing Subdomain",
                        f"Brand '{brand}' appears as a deceptive subdomain under '{root_domain}'.",
                        75.0
                    ))
                    score += 75.0
                    break
                # If brand is hyphenated into a domain (e.g. chase-login-security.com)
                elif brand in root_domain and root_domain != f"{brand}.com" and root_domain != f"{brand}.org":
                    indicators.append(URLIndicator(
                        "Brand Name Combination",
                        f"Targeted brand '{brand}' appears combined inside domain '{root_domain}'.",
                        50.0
                    ))
                    score += 50.0
                    break

        # 4. Excessive Subdomain Structure
        if len(domain_parts) >= 4:
            indicators.append(URLIndicator(
                "Excessive Subdomain Depth",
                f"URL has {len(domain_parts)} domain levels, common in evasive phishing URLs.",
                35.0
            ))
            score += 35.0

        # 5. URL Shorteners in Context
        for shortener in self.shorteners:
            if domain == shortener or domain.endswith("." + shortener):
                indicators.append(URLIndicator(
                    "URL Shortener",
                    f"Uses generic URL shortening service ({domain}) masking final destination.",
                    30.0
                ))
                score += 30.0
                break

        # 6. High-Risk TLD
        tld = domain_parts[-1] if domain_parts else ""
        if tld in self.suspicious_tlds:
            indicators.append(URLIndicator(
                "High-Risk TLD",
                f"Domain uses high-abuse top level domain (.{tld}).",
                30.0
            ))
            score += 30.0

        # 7. Non-HTTPS URL (Weak signal, not proof of fraud by itself)
        if raw_url.startswith("http://"):
            indicators.append(URLIndicator(
                "Unencrypted HTTP Protocol",
                "URL uses unencrypted http:// rather than secure https://.",
                15.0
            ))
            score += 15.0

        # 8. Suspicious Keywords in Path or Query
        suspicious_keywords = ["verify", "login", "signin", "secure", "account", "update", "banking", "kyc"]
        for kw in suspicious_keywords:
            if kw in path:
                # If path has banking keywords but domain is suspicious or shortener
                if score >= 25.0:
                    indicators.append(URLIndicator(
                        "Sensitive Action Path",
                        f"URL path targets sensitive action keyword '{kw}'.",
                        20.0
                    ))
                    score += 20.0
                    break

        # Normalize score 0 to 100
        normalized_score = min(100.0, max(0.0, score))
        is_suspicious = normalized_score >= 40.0

        explanations = [f"{ind.name}: {ind.description}" for ind in indicators]

        return URLAnalysisResult(
            url=raw_url,
            domain=domain,
            risk_score=normalized_score,
            is_suspicious=is_suspicious,
            indicators=indicators,
            explanations=explanations
        )

    def analyze_all(self, text: str) -> List[URLAnalysisResult]:
        """Extract and analyze all URLs found in the text."""
        urls = self.extract_urls(text)
        return [self.analyze_url(u) for u in urls]

