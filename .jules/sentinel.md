## 2025-02-19 - URL Validation Bypass (XSS / CRLF Injection)
**Vulnerability:** URL indicator validation only checked if the input string started with `http://` or `https://` (`startswith()`). This allowed malicious users to ingest URLs containing injected newlines (`\n`) or XSS payloads (`<script>`).
**Learning:** `startswith()` is structurally insufficient for validating complex string formats like URLs where malicious payloads can be appended at the end of the string.
**Prevention:** Always use strict regex (e.g., `^https?://[^\s<>"'\`]+\Z`) with absolute termination (`\Z`) or a dedicated URL parser to enforce boundaries and exclude forbidden characters like whitespace and angle brackets.
