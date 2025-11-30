# Web Payment Scanner - Usage Guide

##  Quick Start

### 1. Basic Scan
Scan a target URL with default settings:
```bash
./bin/scanner --target https://example.com/payment
```

### 2. Authenticated Scan
Provide a login URL to authenticate before scanning:
```bash
./bin/scanner --target https://example.com/checkout --login https://example.com/login
```
The scanner will launch a browser and wait for you to log in manually. Once it detects a successful login, it will extract your session cookies and proceed with the scan.

### 3. Headless Mode
Run without visible browser window (good for CI/CD):
```bash
./bin/scanner --target https://example.com --headless
```

---

##  Command Line Options

| Flag | Shorthand | Description | Default |
|------|-----------|-------------|---------|
| `--target` | `-u` | Target URL to scan (Required) | - |
| `--login` | `-l` | Login URL for authentication | - |
| `--output` | `-o` | Output directory for reports | `./reports` |
| `--browser` | `-b` | Browser type (firefox, chromium, webkit) | `firefox` |
| `--headless` | | Run browser in headless mode | `false` |
| `--verbose` | `-v` | Enable verbose logging | `false` |
| `--timeout` | `-t` | Login timeout in seconds | `300` |

### Discovery Flags
Disable specific discovery modules:
```bash
--crawl=false          # Disable crawler
--wayback=false        # Disable Wayback Machine
--common-paths=false   # Disable path brute-forcing
--js-analysis=false    # Disable JS analysis
```

### Scanner Flags
Disable specific vulnerability checks:
```bash
--race=false           # Disable Race Condition check
--price=false          # Disable Price Manipulation check
--idor=false           # Disable IDOR check
--otp=false            # Disable OTP check
--callback=false       # Disable Callback check
--amount=false         # Disable Amount Validation check
--idempotency=false    # Disable Idempotency check
```

---

##  Reports

Reports are generated in the `reports/` directory by default:

1. **HTML Report** (`scan_report_TIMESTAMP.html`): Visual report with summary and details.
2. **JSON Report** (`scan_report_TIMESTAMP.json`): Raw data for integration with other tools.
3. **Console Output**: Real-time progress and summary table.

---

## 💡 Examples

**Full scan on a staging environment:**
```bash
./bin/scanner -u https://staging.store.com/checkout -l https://staging.store.com/login -v
```

**Quick scan for race conditions only:**
```bash
./bin/scanner -u https://shop.com/claim-coupon --crawl=false --wayback=false --price=false --idor=false
```

**Scan using Chromium instead of Firefox:**
```bash
./bin/scanner -u https://app.com -b chromium
```
