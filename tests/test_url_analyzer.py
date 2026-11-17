"""
CyberGuard Desktop - Automated Test Suite for URL Analyzer
Tests URL extraction, IP addresses, brand spoofing subdomains, and legitimate URLs.
"""

import pytest
from detection.url_analyzer import URLAnalyzer


@pytest.fixture
def analyzer():
    return URLAnalyzer()


def test_url_extraction(analyzer):
    text = "Visit our update portal at https://secure-bank-login.com/auth or http://bit.ly/3xY7k for details."
    urls = analyzer.extract_urls(text)
    assert len(urls) == 2
    assert "https://secure-bank-login.com/auth" in urls
    assert "http://bit.ly/3xY7k" in urls


def test_ip_address_url(analyzer):
    res = analyzer.analyze_url("http://192.168.1.105/bank/login.php")
    assert res.is_suspicious is True
    assert res.risk_score >= 70.0
    assert any("Direct IP Host" in ind.name for ind in res.indicators)


def test_brand_spoofing_subdomain(analyzer):
    res = analyzer.analyze_url("https://paypal.com.account-update.xyz/login")
    assert res.is_suspicious is True
    assert res.risk_score >= 70.0
    assert any("Brand Spoofing Subdomain" in ind.name for ind in res.indicators)


def test_url_shortener(analyzer):
    res = analyzer.analyze_url("http://bit.ly/verify-account")
    assert any("URL Shortener" in ind.name for ind in res.indicators)
    assert res.risk_score >= 30.0


def test_legitimate_url(analyzer):
    res = analyzer.analyze_url("https://www.google.com/search?q=cybersecurity")
    assert res.is_suspicious is False
    assert res.risk_score <= 20.0
    assert len(res.indicators) == 0 or all(ind.score < 30.0 for ind in res.indicators)

