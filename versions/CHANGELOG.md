# Changelog

All notable changes to the SQL Injection Detection Rule Engine will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-10-18

### Added
- Initial rule catalog with 59 detection rules
- 6 attack categories: Tautology, UNION, Comment, Stacked, Time-Based, Advanced
- Weighted sum decision logic
- Rule priority system (1-20 scale)
- Confidence scoring (0.0-1.0)
- Hot-reload capability
- Comprehensive test dataset (119 samples)

### Security
- CRITICAL severity rules for xp_cmdshell, DROP TABLE, GRANT ALL
- Time-based blind injection detection
- Advanced obfuscation detection (hex, URL encoding, CHAR)

## [Unreleased]

### Planned
- Machine learning enhancement (Phase 4)
- Additional evasion techniques
- Performance optimizations
- Extended test coverage
