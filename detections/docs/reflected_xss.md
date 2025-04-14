## Overview

Detect reflected cross-site scripting attacks in Nginx access logs where malicious scripts are injected into URLs or form inputs. This detection identifies attempts to inject client-side scripts into web pages viewed by other users, which can lead to session hijacking, defacement, or redirection to malicious sites.

The detection focuses on identifying common XSS patterns, including script tags, JavaScript event handlers, and other HTML injection vectors that might be used to execute malicious code in users' browsers.

**References**:
- [OWASP Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 