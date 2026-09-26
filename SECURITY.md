# Security Policy

FEINT is a defensive research tool. It trains and attacks models on feature vectors only; it does not capture, craft or transmit network traffic.

## Reporting a vulnerability
Please open a private security advisory on the repository (GitHub "Report a vulnerability") or email the maintainer. Do not file public issues for security bugs. Expect acknowledgement within 7 days.

## Scope
- In scope: unsafe parsing of input files, dependency vulnerabilities, code execution through CLI arguments.
- Out of scope: "the detector can be evaded" — measuring that is the point of the project; open a normal issue with a reproducible robustness finding instead.

## Safe use
Only use real traffic datasets you are licensed to use (e.g. CIC-IDS2017). Any lab traffic capture must happen in an isolated network you own.
