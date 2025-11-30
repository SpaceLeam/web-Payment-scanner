# Web Payment Scanner - Complete Usage Guide

## Table of Contents
1. [Quick Start](#quick-start)
2. [All Available Flags](#all-available-flags)
3. [Command Variations](#command-variations)
4. [Scanner Categories](#scanner-categories)
5. [Real-World Examples](#real-world-examples)
6. [Best Practices](#best-practices)

---

## Quick Start

### Basic Scan (All Tests Enabled)
```bash
./bin/scanner --target https://payment.example.com
```

### Authenticated Scan
```bash
./bin/scanner \
  --target https://app.example.com/checkout \
  --login https://app.example.com/login
```

### Headless Mode (CI/CD)
```bash
./bin/scanner \
  --target https://staging.example.com \
  --headless \
  --output reports/staging
```

---

## All Available Flags

### Core Flags
| Flag | Short | Type | Default | Description |
|------|-------|------|---------|-------------|
| `--target` | `-u` | string | **required** | Target URL to scan |
| `--login` | `-l` | string | - | Login URL for authentication |
| `--output` | `-o` | string | `reports` | Output directory |
| `--browser` | `-b` | string | `firefox` | Browser type (firefox/chromium/webkit) |
| `--headless` | - | bool | `false` | Run browser without GUI |
| `--verbose` | `-v` | bool | `false` | Verbose logging |
| `--timeout` | `-t` | int | `300` | Login timeout (seconds) |
| `--depth` | `-d` | int | `3` | Max crawl depth |
| `--wordlist` | `-w` | string | `configs/wordlists/payment_paths.txt` | Wordlist path |
| `--no-cache` | - | bool | `false` | Skip session cache (force re-login) |

### Discovery Flags (Control Endpoint Discovery)
| Flag | Default | Description |
|------|---------|-------------|
| `--crawl` | `true` | Enable web crawler |
| `--wayback` | `true` | Enable Wayback Machine API |
| `--common-paths` | `true` | Enable path bruteforce |
| `--js-analysis` | `true` | Enable JavaScript analysis |

### Vulnerability Scanner Flags

#### Original Scanners (Already Implemented)
| Flag | Default | CWE | CVSS | Description |
|------|---------|-----|------|-------------|
| `--race` | `true` | CWE-362 | 9.1 | Race condition testing |
| `--price` | `true` | CWE-20 | 8.5 | Price manipulation |
| `--idor` | `true` | CWE-639 | 7.5 | IDOR testing |
| `--otp` | `true` | CWE-307 | 6.5 | OTP brute force |
| `--callback` | `true` | CWE-294/290/327 | 7.5-8.1 | Webhook security |
| `--amount` | `true` | CWE-20/682 | 5.3-8.1 | Amount validation |
| `--idempotency` | `true` | CWE-837 | 7.5 | Idempotency bypass |

#### New Scanners (November 2025)
| Flag | Default | CWE | CVSS | Description |
|------|---------|-----|------|-------------|
| `--sql` | `true` | CWE-89 | 9.8 | SQL injection (8 payloads) |
| `--nosql` | `true` | CWE-943 | 7.5-9.8 | NoSQL injection (MongoDB) |
| `--jwt` | `true` | CWE-347/613 | 7.5-10.0 | JWT vulnerabilities |
| `--graphql` | `true` | CWE-200/770/799 | 6.5-9.1 | GraphQL security |

#### WebSocket Flags
| Flag | Default | Description |
|------|---------|-------------|
| `--ws-intercept` | `true` | Enable WebSocket interceptor |

---

## Command Variations

### 1. Basic Scans

#### Full Scan (All Tests)
```bash
./bin/scanner --target https://api.example.com
```

#### With Authentication
```bash
./bin/scanner \
  --target https://app.example.com/payment \
  --login https://app.example.com/auth/login \
  --timeout 600
```

#### Custom Output Directory
```bash
./bin/scanner \
  --target https://shop.example.com \
  --output ./security-reports/$(date +%Y%m%d)
```

#### Different Browser
```bash
# Chromium
./bin/scanner --target https://example.com --browser chromium

# WebKit (Safari)
./bin/scanner --target https://example.com --browser webkit
```

---

### 2. Focused Testing

#### Only Race Conditions
```bash
./bin/scanner \
  --target https://promo.example.com/claim-coupon \
  --race=true \
  --price=false --idor=false --otp=false \
  --callback=false --amount=false --idempotency=false \
  --sql=false --nosql=false --jwt=false --graphql=false
```

#### Only Injection Tests (SQL + NoSQL)
```bash
./bin/scanner \
  --target https://api.example.com/payments \
  --sql=true --nosql=true \
  --race=false --price=false --idor=false --otp=false \
  --callback=false --amount=false --idempotency=false \
  --jwt=false --graphql=false
```

#### Only Authentication Tests (JWT + OTP + Callback)
```bash
./bin/scanner \
  --target https://auth.example.com \
  --jwt=true --otp=true --callback=true \
  --race=false --price=false --idor=false \
  --amount=false --idempotency=false \
  --sql=false --nosql=false --graphql=false
```

#### GraphQL-Specific Scan
```bash
./bin/scanner \
  --target https://api.example.com/graphql \
  --graphql=true \
  --race=false --price=false --idor=false --otp=false \
  --callback=false --amount=false --idempotency=false \
  --sql=false --nosql=false --jwt=false
```

---

### 3. Discovery Control

#### Disable All Discovery (Direct URL Testing)
```bash
./bin/scanner \
  --target https://api.example.com/v1/checkout \
  --crawl=false \
  --wayback=false \
  --common-paths=false \
  --js-analysis=false
```

#### Only Wayback Machine Discovery
```bash
./bin/scanner \
  --target https://old.example.com \
  --crawl=false \
  --wayback=true \
  --common-paths=false \
  --js-analysis=false
```

#### Custom Wordlist
```bash
./bin/scanner \
  --target https://api.example.com \
  --wordlist ./custom-wordlists/payment-endpoints.txt \
  --common-paths=true
```

#### Deep Crawl
```bash
./bin/scanner \
  --target https://shop.example.com \
  --depth 10 \
  --crawl=true
```

---

### 4. Advanced Combinations

#### Bug Bounty Full Scan
```bash
./bin/scanner \
  --target https://target.hackerone.com/checkout \
  --login https://target.hackerone.com/login \
  --verbose \
  --depth 5 \
  --timeout 900 \
  --output ./bug-bounty-reports/$(date +%Y%m%d-%H%M%S)
```

#### Stealth Mode (Avoid WAF Detection)
```bash
./bin/scanner \
  --target https://waf-protected.example.com \
  --headless \
  --crawl=false \
  --wayback=false \
  --common-paths=false \
  --depth 1
```

#### Quick Smoke Test
```bash
./bin/scanner \
  --target https://staging.example.com \
  --race=true --price=true --sql=true \
  --idor=false --otp=false --callback=false \
  --amount=false --idempotency=false \
  --nosql=false --jwt=false --graphql=false \
  --crawl=false --wayback=false
```

#### CI/CD Pipeline
```bash
./bin/scanner \
  --target https://staging-api.example.com \
  --headless \
  --no-cache \
  --output ./test-results \
  --timeout 120
```

---

## Real-World Examples

### Example 1: E-commerce Checkout Flow
```bash
./bin/scanner \
  --target https://shop.example.com/checkout \
  --login https://shop.example.com/account/login \
  --race=true \
  --price=true \
  --amount=true \
  --idempotency=true \
  --sql=true \
  --verbose
```
**Tests**: Race conditions on coupon codes, price tampering, amount validation, SQL injection in payment ID

---

### Example 2: GraphQL Payment API
```bash
./bin/scanner \
  --target https://api.example.com/graphql \
  --graphql=true \
  --jwt=true \
  --race=true \
  --crawl=false \
  --wayback=false \
  --common-paths=false
```
**Tests**: GraphQL introspection, depth limits, batch attacks, JWT vulnerabilities

---

### Example 3: Mobile App Backend
```bash
./bin/scanner \
  --target https://mobile-api.example.com \
  --jwt=true \
  --nosql=true \
  --race=true \
  --idor=true \
  --crawl=false \
  --headless
```
**Tests**: JWT auth bypass, NoSQL injection (MongoDB), race conditions, IDOR

---

### Example 4: Payment Gateway Integration
```bash
./bin/scanner \
  --target https://payments.example.com \
  --callback=true \
  --amount=true \
  --idempotency=true \
  --race=true \
  --sql=true \
  --verbose
```
**Tests**: Webhook signature validation, amount manipulation, idempotency key bypass, race conditions

---

### Example 5: WebSocket-Based Real-time Payment
```bash
./bin/scanner \
  --target https://realtime.example.com \
  --login https://realtime.example.com/login \
  --ws-intercept=true \
  --race=true \
  --price=true \
  --jwt=true
```
**Tests**: WebSocket race conditions, message replay, amount manipulation via WS

---

## Scanner Categories

### Category 1: Business Logic Flaws
```bash
# Race Conditions, Price Manipulation, Idempotency
./bin/scanner --target <URL> \
  --race=true --price=true --idempotency=true \
  --idor=false --otp=false --callback=false \
  --amount=false --sql=false --nosql=false \
  --jwt=false --graphql=false
```

### Category 2: Injection Attacks
```bash
# SQL, NoSQL, GraphQL injection
./bin/scanner --target <URL> \
  --sql=true --nosql=true --graphql=true \
  --race=false --price=false --idor=false \
  --otp=false --callback=false --amount=false \
  --idempotency=false --jwt=false
```

### Category 3: Authentication & Authorization
```bash
# IDOR, JWT, OTP, Callback
./bin/scanner --target <URL> \
  --idor=true --jwt=true --otp=true --callback=true \
  --race=false --price=false --amount=false \
  --idempotency=false --sql=false --nosql=false \
  --graphql=false
```

### Category 4: Input Validation
```bash
# Amount validation, Price manipulation, SQL/NoSQL injection
./bin/scanner --target <URL> \
  --amount=true --price=true --sql=true --nosql=true \
  --race=false --idor=false --otp=false \
  --callback=false --idempotency=false \
  --jwt=false --graphql=false
```

---

## Best Practices

### 1. Always Start with Discovery
```bash
# First run: Full discovery, no scans
./bin/scanner --target <URL> \
  --crawl=true --wayback=true --common-paths=true \
  --race=false --price=false --idor=false --otp=false \
  --callback=false --amount=false --idempotency=false \
  --sql=false --nosql=false --jwt=false --graphql=false
```

### 2. Session Caching for Faster Re-scans
```bash
# First run: Login and cache session
./bin/scanner --target <URL> --login <LOGIN_URL>

# Subsequent runs: Use cached session
./bin/scanner --target <URL>
# Session valid for 6 hours

# Force re-login
./bin/scanner --target <URL> --login <LOGIN_URL> --no-cache
```

### 3. Verbose Mode for Debugging
```bash
./bin/scanner --target <URL> --verbose
# Shows detailed logs, request/response info
```

### 4. Incremental Testing
```bash
# Step 1: Test race conditions
./bin/scanner --target <URL> --race=true --price=false --idor=false ...

# Step 2: Test price manipulation
./bin/scanner --target <URL> --race=false --price=true --idor=false ...

# Step 3: Test injections
./bin/scanner --target <URL> --race=false --price=false --sql=true ...
```

### 5. Custom Report Naming
```bash
# By date
./bin/scanner --target <URL> --output reports/scan-$(date +%Y%m%d)

# By target domain
DOMAIN=$(echo <URL> | awk -F/ '{print $3}')
./bin/scanner --target <URL> --output reports/$DOMAIN
```

---

## Troubleshooting

### Login Timeout
```bash
# Increase timeout to 15 minutes
./bin/scanner --target <URL> --login <LOGIN_URL> --timeout 900
```

### WAF Blocking
```bash
# Reduce crawl depth and disable aggressive discovery
./bin/scanner --target <URL> \
  --depth 1 \
  --common-paths=false \
  --wayback=false
```

### Browser Crashes
```bash
# Use headless mode
./bin/scanner --target <URL> --headless

# Or switch browser
./bin/scanner --target <URL> --browser chromium
```

### Session Expired Mid-Scan
```bash
# Use fresh session
./bin/scanner --target <URL> --login <LOGIN_URL> --no-cache
```

---

## Output Files

Every scan generates:
1. **JSON Report**: `reports/scan_report_YYYYMMdd_HHmmss.json`
2. **HTML Report**: `reports/scan_report_YYYYMMdd_HHmmss.html`
3. **Console Summary**: Real-time output with color-coded severity

### View Reports
```bash
# Open HTML report
firefox reports/scan_report_*.html

# Parse JSON results
cat reports/scan_report_*.json | jq '.Vulnerabilities[] | select(.Severity=="CRITICAL")'
```

---

## Quick Reference Card

### Minimal Scan
```bash
./bin/scanner -u https://example.com
```

### Full Authenticated Scan
```bash
./bin/scanner -u <TARGET> -l <LOGIN> -v -o ./reports
```

### GraphQL Only
```bash
./bin/scanner -u <URL>/graphql --graphql=true --race=false --price=false ...
```

### SQL/NoSQL Only
```bash
./bin/scanner -u <URL> --sql=true --nosql=true --race=false ...
```

### Disable All Scanners (Discovery Only)
```bash
./bin/scanner -u <URL> \
  --race=false --price=false --idor=false --otp=false \
  --callback=false --amount=false --idempotency=false \
  --sql=false --nosql=false --jwt=false --graphql=false
```

---

## All 21 Scanners Summary

| # | Scanner | Flag | CWE | CVSS | Status |
|---|---------|------|-----|------|--------|
| 1 | Race Condition | `--race` | CWE-362 | 9.1 | Available |
| 2 | Price Manipulation | `--price` | CWE-20 | 8.5 | Available |
| 3 | IDOR | `--idor` | CWE-639 | 7.5 | Available |
| 4 | OTP Brute Force | `--otp` | CWE-307 | 6.5 | Available |
| 5 | Webhook Replay | `--callback` | CWE-294 | 7.5 | Available |
| 6 | IP Spoofing | `--callback` | CWE-290 | 8.1 | Available |
| 7 | Weak HMAC | `--callback` | CWE-327 | 7.5 | Available |
| 8 | Currency Mismatch | `--amount` | CWE-20 | 8.1 | Available |
| 9 | WS Cleartext | `--ws-intercept` | CWE-319 | 7.5 | Available |
| 10 | WS Missing Auth | `--ws-intercept` | CWE-306 | 8.1 | Available |
| 11 | SQL Injection | `--sql` | CWE-89 | 9.8 | Available |
| 12 | NoSQL Injection | `--nosql` | CWE-943 | 9.8 | Available |
| 13 | NoSQL Regex DoS | `--nosql` | CWE-1333 | 7.5 | Available |
| 14 | JWT alg:none | `--jwt` | CWE-347 | 10.0 | Available |
| 15 | JWT Expiration | `--jwt` | CWE-613 | 7.5 | Available |
| 16 | JWT Claims | `--jwt` | CWE-347 | 9.8 | Available |
| 17 | GraphQL Introspection | `--graphql` | CWE-200 | 7.5 | Available |
| 18 | GraphQL Depth Limit | `--graphql` | CWE-770 | 7.5 | Available |
| 19 | GraphQL Batch Attack | `--graphql` | CWE-799 | 6.5 | Available |
| 20 | GraphQL Field Dup | `--graphql` | CWE-1333 | 5.3 | Available |
| 21 | GraphQL Auth Bypass | `--graphql` | CWE-306 | 9.1 | Available |

**Total: 21 vulnerability tests across 11 CLI flags**

---

**Last Updated**: November 30, 2025  
**Version**: 0.3.0 (with GraphQL, SQL, NoSQL, JWT support)
