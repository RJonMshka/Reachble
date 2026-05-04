# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please **do not open a public GitHub issue** for security vulnerabilities.

Email **kumarrajat13th@gmail.com** with:

- A description of the vulnerability
- Steps to reproduce
- Any proof-of-concept code

You'll get an acknowledgement within 48 hours and a resolution timeline within 7 days.

## Scope

Reachble is a local static-analysis tool. It reads your project files and makes network requests to OSV.dev, NVD, GHSA, and EPSS. It writes to `~/.cache/reachble/` and the project directory only.

Vulnerabilities in scope: output that could mislead a user into marking a reachable CVE as `not_affected`, incorrect VEX justifications, filesystem access outside the stated boundaries, or unintended network calls.
