# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-11-30

### Added
- Initial project setup with November 2025 dependencies
- Core data models (ScanConfig, Session, Endpoint, Vulnerability, ScanResult)
- Browser automation module using Playwright v0.5200.1
  - Firefox support with anti-detection features
  - Manual login workflow
  - Session extraction (cookies, localStorage, sessionStorage)
  - Network request/response interception
- Utility modules:
  - HTTP client with TLS support
  - Colored logger using fatih/color v1.18.0
  - Input validation for URLs and domains
- CLI interface using Cobra v1.10.1
  - `test` command for browser automation testing
  - Verbose mode and browser selection flags
- Payment endpoint wordlist (100+ common paths)
- Legal documentation and disclaimers
- MIT License
- Comprehensive README with badges and features

### Dependencies
- Go 1.22+
- github.com/playwright-community/playwright-go v0.5200.1
- github.com/spf13/cobra v1.10.1
- github.com/fatih/color v1.18.0
- github.com/olekukonko/tablewriter v1.1.1
- github.com/schollz/progressbar/v3 v3.14.1
- golang.org/x/sync v0.8.0

### Notes
- This is an early development version
- For authorized penetration testing only
- Discovery and scanning modules coming in v0.2.0

[0.1.0]: https://github.com/SpaceLeam/web-Payment-scanner/releases/tag/v0.1.0
