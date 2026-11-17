# CyberGuard Desktop

**CyberGuard Desktop** is an autonomous, privacy-conscious Windows 11 desktop security assistant that monitors visible screen content across all connected displays and identifies potential phishing attacks, scam solicitations, social engineering attempts, and suspicious URLs in real-time.

Built as an independent security layer, CyberGuard works universally across any web browser (Chrome, Edge, Firefox, Brave) and native desktop application without requiring browser extensions, remote proxy tunnels, or cloud APIs.

---

## 1. Key Architectural Principles & Features

- **Multi-Monitor Display Awareness**: Leverages high-performance MSS screen capture to enumerate and inspect all physical displays individually, not just the primary monitor.
- **Intelligent Screen-Change Detection**: Uses OpenCV downscaling, grayscale conversion, and pixel difference thresholds to eliminate redundant OCR cycles when display content is static (e.g., ignoring micro-jitters and blinking cursors).
- **In-Memory Zero-Retention Pipeline**: Screen captures and OCR text buffers exist strictly in volatile memory. No screenshots or raw OCR texts are ever saved to disk or transmitted over the network.
- **Explainable Weighted Risk Engine**: Evaluates threats based on a transparent, calibrated mathematical formula:
  $$\text{Risk Score} = 0.30U + 0.25P + 0.20I + 0.15L + 0.10C$$
  *(Where $U$ = Urgency, $P$ = Payment Request, $I$ = Impersonation, $L$ = URL Risk, $C$ = Credential Theft).*
- **Temporal Event Correlation**: Retains a short-lived rolling memory (configurable 60-second window) to correlate multi-stage scam sequences (e.g., Urgent KYC Warning $\rightarrow$ Suspicious Shortened URL $\rightarrow$ OTP Solicitation Page).
- **Local SQLite Threat Vault**: Stores sanitized threat metadata (timestamp, risk score, severity category, sanitized explanation, domain, and monitor ID) with automated credential redaction.
- **Non-Intrusive Alert Overlay & System Tray**: Discretely notifies the user with a floating bottom-right advisory when risk scores exceed the threshold, while running unobtrusively in the Windows System Tray.

---

## 2. Technical Limitation Notice

> **Important Technical Limitation**: CyberGuard Desktop can analyze **only content visibly rendered on captured displays**. It cannot inspect hidden browser tabs, minimized applications, background system memory, end-to-end encrypted messaging content that is not rendered on screen, or DRM-protected video surfaces that Windows screen capture APIs cannot read. CyberGuard never claims to replace full antivirus or endpoint detection platforms.

---

## 3. Technology Stack

- **GUI Framework**: PySide6 (Qt for Python 6.12+)
- **System Tray**: `QSystemTrayIcon` with background lifecycle preservation
- **Screen Capture**: `mss` 10.2+
- **Computer Vision**: OpenCV (`opencv-python` 4.13+) & `numpy`
- **OCR Engine**: Tesseract OCR (via `pytesseract` 0.3+)
- **Database**: SQLite3 (Standard Library)
- **URL & Heuristic Engine**: Python standard library (`urllib.parse`, `re`)
- **Testing**: `pytest`
- **Packaging**: PyInstaller 6.22+

---

## 4. Project Structure

```
CyberGuard/
├── main.py                     # Application entry point and signal orchestrator
├── config.py                   # Central configuration & auto-detection
├── requirements.txt            # Python dependencies
├── README.md                   # Complete architectural and operations manual
│
├── desktop/                    # Desktop GUI Layer (PySide6)
│   ├── __init__.py
│   ├── main_window.py          # Main application window & stat cards
│   ├── tray.py                 # Windows system tray integration
│   ├── alert_overlay.py        # Frameless floating warning overlay
│   ├── threat_history.py       # Threat history table and event inspector
│   └── settings.py             # Settings modal dialog
│
├── monitoring/                 # Screen Capture & Vision Layer
│   ├── __init__.py
│   ├── screen_capture.py       # Multi-monitor MSS capture manager
│   ├── screen_change.py        # OpenCV visual change detector
│   ├── ocr_engine.py           # In-memory Tesseract OCR engine
│   └── monitor_worker.py       # Safe asynchronous QThread background worker
│
├── detection/                  # Threat Intelligence & Scoring
│   ├── __init__.py
│   ├── scam_rules.py           # Contextual regex rules and anti-false-positive mitigators
│   ├── url_analyzer.py         # Static URL and domain heuristic parser
│   ├── risk_engine.py          # Weighted explainable risk calculator
│   ├── event_correlation.py    # Short-lived sliding window correlation engine
│   └── text_classifier.py     # Optional scikit-learn classifier interface
│
├── database/                   # Persistence Layer
│   ├── __init__.py
│   ├── database.py             # SQLite connection and schema management
│   └── history.py              # Sanitized threat event repository
│
├── utils/                      # Utilities & Safeguards
│   ├── __init__.py
│   ├── text_cleaner.py         # OCR token normalizer and noise filter
│   ├── privacy.py              # Credential redaction and active window exclusions
│   └── logger.py               # Privacy-preserving logging system
│
├── assets/                     # Graphical assets
│   └── icons/                  # High-DPI application and shield icons
│
└── tests/                      # Automated Test Suite
    ├── test_scam_rules.py      # Unit tests for scam patterns & legitimate contexts
    ├── test_url_analyzer.py    # Unit tests for URL heuristics and IP hosts
    ├── test_risk_engine.py     # Unit tests for scoring formulas & boundaries
    ├── test_ocr.py             # Unit tests for OCR handling & privacy redaction
    └── test_scenarios.py       # Labeled scenario test suite
```

---

## 5. Prerequisites & Installation

### Step 1: Install Python
Ensure Python 3.11, 3.12, or 3.14 is installed:
```powershell
python --version
```

### Step 2: Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### Step 3: Install Tesseract OCR (External Requirement)
CyberGuard relies on Tesseract OCR for text extraction.
1. Download the Windows 64-bit installer from the official repository:
   [https://github.com/UB-Mannheim/tesseract/wiki](https://github.com/UB-Mannheim/tesseract/wiki)
2. Run the installer and install to the default location (`C:\Program Files\Tesseract-OCR`).
3. If installed to a custom directory, open **CyberGuard -> Settings** and set the path to `tesseract.exe`.
*(Note: CyberGuard detects missing Tesseract gracefully and alerts the user in the UI without crashing).*

---

## 6. Running CyberGuard Desktop

To launch the desktop interface:
```powershell
python main.py
```

### User Interface Controls
- **Start Monitoring**: Launches the background monitoring worker thread.
- **Pause**: Temporarily suspends screen capture without terminating the worker.
- **Stop**: Halts screen capture and releases capture resources.
- **Scan Now**: Immediately triggers a capture and inspection cycle across all screens.
- **Settings**: Opens configuration for capture intervals, change thresholds, alert sensitivity, and window title exclusions.
- **Clear History**: Purges recorded threats from the local SQLite database.

---

## 7. Running Automated Tests

Run the complete 26-test automated suite using `pytest`:
```powershell
python -m pytest -v
```

All tests execute in ~1.3 seconds, verifying:
- Urgency, Impersonation, Advance Fee, Credential Theft, and Fake Job patterns
- Legitimate bank alerts (false-positive mitigation)
- Legitimate job listings
- Static URL heuristics (IP hosts, brand spoofing subdomains, URL shorteners)
- Mathematical risk score boundaries (Low, Suspicious, High, Critical)
- Sliding-window event correlation
- In-memory OCR error handling and sensitive data redaction

---

## 8. College Project Manual Testing Guide

To test CyberGuard manually against test scenarios, display any of the following texts in Notepad, a web page, or an image:

### Scenario 1: WhatsApp-Style Family Emergency Scam
- **Test Content**:
  ```text
  URGENT: Hi Mom, my phone broke and I am using this temporary number.
  I need to pay a bill right now or my account will be blocked.
  Please transfer $450 immediately to http://bit.ly/quick-send-fund
  ```
- **Expected Result**: **High Risk (Score $\ge 60$)**
- **Triggered Indicators**: High urgency trigger, Family contact impersonation lure, Direct fund transfer solicitation, URL shortener.

### Scenario 2: Fake Bank KYC Notice with Credential Solicitation
- **Test Content**:
  ```text
  Dear State Bank customer, your KYC verification has expired today.
  To avoid account suspension, click here to update:
  http://192.168.1.45/sbi/verify-login and enter your OTP.
  ```
- **Expected Result**: **High / Critical Risk (Score $\ge 70$)**
- **Triggered Indicators**: Major banking institution mention, Urgent KYC verification, Raw IP host URL, Sensitive OTP harvesting solicitation.

### Scenario 3: High-Yield Crypto Investment Scheme
- **Test Content**:
  ```text
  Exclusive opportunity: Guaranteed returns of 25% daily!
  100% risk-free crypto investment scheme. Double your money within 48 hours.
  Send crypto to http://guaranteed-profit.crypto-growth.xyz/invest
  ```
- **Expected Result**: **Suspicious / High Risk (Score $\ge 50$)**
- **Triggered Indicators**: Guaranteed returns promise, Crypto investment scheme, High-risk `.xyz` domain, Fund transfer solicitation.

### Scenario 4: Fake Job Requiring Upfront Registration Fee
- **Test Content**:
  ```text
  Hiring immediate remote assistants! Guaranteed employment with $500 daily profit.
  Pay registration fee of $99 for the starter kit before you can start working.
  ```
- **Expected Result**: **Suspicious / High Risk (Score $\ge 55$)**
- **Triggered Indicators**: Immediate urgency, Guaranteed employment claim, Starter kit payment requirement, Advance registration fee.

### Scenario 5: Legitimate Banking Transaction Advisory (False-Positive Test)
- **Test Content**:
  ```text
  HDFC Bank Alert: Rs. 1,500 debited from A/C **4921 at 14:20.
  If this was not you, call 1800-202-6161. Never share your OTP or password with anyone.
  Bank never asks for confidential details.
  ```
- **Expected Result**: **Low Risk (Score $< 30$)**
- **Verification**: Mitigating safety language (*"Never share your OTP or password with anyone"*) actively dampens the score, ensuring no false alert is triggered.

### Scenario 6: Normal Technical Web Content
- **Test Content**:
  ```text
  Python is a high-level, general-purpose programming language.
  Its design philosophy emphasizes code readability with the use of significant indentation.
  Documentation available at https://docs.python.org/3/
  ```
- **Expected Result**: **Low Risk (Score $< 15$)**
- **Verification**: 0 categories detected. Status badge remains Clean / Low Risk.

---

## 9. Building the Windows Executable (PyInstaller)

To compile CyberGuard Desktop into a standalone Windows executable bundle:

```powershell
python -m PyInstaller --noconfirm --onedir --windowed --name "CyberGuard" --icon "assets/icons/shield.png" --add-data "assets;assets" main.py
```

The resulting executable will be generated at:
```
dist/CyberGuard/CyberGuard.exe
```

Run `dist\CyberGuard\CyberGuard.exe` to launch the packaged desktop application.

---

## 10. Privacy & Security Guarantees

1. **Local-Only Processing**: CyberGuard initiates zero outbound HTTP/HTTPS network requests, zero DNS requests, and zero telemetry collection.
2. **No Persistent Screen Captures**: Frames captured via MSS are stored in temporary memory buffers and discarded immediately after difference analysis and OCR.
3. **Sensitive Credential Scrubbing**: Any OTP numbers, payment card digits, or password tokens detected during text analysis are redacted (`[REDACTED]`) prior to entering SQLite logs or the UI.
4. **Active Application Exclusions**: Users can specify window title keywords (e.g. `KeePass`, `Bitwarden`, `1Password`) in Settings to suspend OCR analysis whenever sensitive credential managers have foreground focus.

