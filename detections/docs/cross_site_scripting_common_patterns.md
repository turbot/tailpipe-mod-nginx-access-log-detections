## Overview

Cross-Site Scripting Common Patterns detection identifies fundamental Cross-Site Scripting (XSS) patterns in HTTP requests and User-Agent headers. Cross-Site Scripting is one of the most prevalent web application security flaws that allows attackers to inject client-side scripts into web pages viewed by other users.

This detection focuses on identifying the most common and widespread XSS attack patterns, including script tags, JavaScript functions like `alert()`, `prompt()`, and `eval()`, as well as document object manipulation attempts. These attacks typically target vulnerable input fields in web applications that fail to properly sanitize or encode user input.

When XSS attacks are successful, attackers can steal cookies, session tokens, or other sensitive information; redirect users to malicious websites; or perform actions on behalf of the victim. Common targets include search fields, comment sections, form inputs, and URL parameters that are reflected back to users without proper sanitization.

The detection helps identify reconnaissance attempts and actual exploitation by monitoring for script tags and common JavaScript functions in both request URIs and User-Agent headers. This comprehensive approach catches attackers attempting to evade detection by placing malicious payloads in HTTP headers rather than request parameters. While many of these patterns may represent false positives in legitimate use cases, their presence in log records often indicates scanning or active exploitation attempts.

**References**:
- [OWASP: Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)