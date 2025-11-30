# Web Payment Scanner

> Automated security scanner for payment flow vulnerabilities

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Playwright](https://img.shields.io/badge/Playwright-v0.5200.1-45ba4b?style=flat&logo=playwright)](https://playwright.dev/)

**WARNING: FOR AUTHORIZED PENETRATION TESTING ONLY**

This tool is designed for security professionals to test payment systems with proper authorization. Unauthorized use is illegal and unethical.

---

## Features

- **Race Condition Detection** - Test for concurrent request vulnerabilities
- **Price Manipulation Testing** - Detect price tampering vulnerabilities
- **IDOR Testing** - Find insecure direct object references
- **OTP Security Analysis** - Test OTP rate limiting and brute force protection
- **Webhook Authentication** - Verify callback signature validation
- **Browser Automation** - Playwright-powered session extraction
- **Comprehensive Reporting** - JSON, HTML, and console output

---

## Quick Start

### Prerequisites

- **Go 1.22+** ([Download](https://go.dev/dl/))
- **Git** ([Download](https://git-scm.com/downloads))

### Installation

```bash
# Clone the repository
git clone git@github.com:SpaceLeam/web-Payment-scanner.git
cd web-Payment-scanner

# Install dependencies (includes Playwright Firefox)
make install-deps

# Build the scanner
make build
```

### Basic Usage

```bash
# Run the scanner
./bin/scanner

# Or run directly without building
make run
```

---

## Tech Stack

- **Language**: Go 1.22
- **Browser Automation**: Playwright v0.5200.1
- **CLI Framework**: Cobra v1.10.1
- **Terminal UI**: 
  - fatih/color v1.18.0
  - tablewriter v1.1.1
  - progressbar v3.14.1

---

## Project Structure

```
web-Payment-scanner/
├── cmd/scanner/           # CLI entry point
├── internal/
│   ├── browser/          # Playwright automation
│   ├── discovery/        # Endpoint discovery
│   ├── scanner/          # Vulnerability scanners
│   ├── models/           # Data structures
│   ├── reporter/         # Report generation
│   └── utils/            # Utilities
├── configs/              # Configuration files
├── docs/                 # Documentation
└── tests/                # Test suites
```

---

## Attack Vectors

### Implemented Tests

1. **Race Conditions**
   - Concurrent request flooding
   - Synchronization barrier testing
   - Multi-coupon/voucher exploitation

2. **Price Manipulation**
   - Negative pricing
   - Zero/near-zero amounts
   - Decimal precision abuse

3. **IDOR (Insecure Direct Object References)**
   - Cross-account resource access
   - Order ID enumeration

4. **OTP/2FA Security**
   - Rate limit bypass
   - Brute force testing

5. **Webhook/Callback Authentication**
   - Signature validation bypass
   - Replay attack testing

---

## Development

### Running Tests

```bash
# Run all tests
make test

# Run with race detection
make test-race

# Format code
make fmt
```

### Building from Source

```bash
# Check Go version
make check-version

# Build binary
make build

# Install to GOPATH/bin
make install
```

---

## Documentation

- [Usage Guide](docs/USAGE.md) - Detailed usage instructions
- [Attack Vectors](docs/ATTACK_VECTORS.md) - Technical details on each test
- [Legal Notice](docs/LEGAL.md) - Important legal information

---

## Legal Notice

**IMPORTANT**: This tool is intended for:
- Authorized security testing of systems you own or have permission to test
- Bug bounty programs with explicit scope
- Educational purposes in controlled environments

**ILLEGAL USES**:
- Testing systems without authorization
- Causing financial harm or fraud
- Any malicious activities

The authors are not responsible for misuse. By using this tool, you agree to use it ethically and legally.

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

---

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

---

## Acknowledgments

- [Playwright Team](https://playwright.dev/) - Browser automation
- [Cobra](https://cobra.dev/) - CLI framework
- Security research community

---

## Contact

For security concerns or questions, please open an issue on GitHub.

**Remember: Use responsibly and ethically.**
