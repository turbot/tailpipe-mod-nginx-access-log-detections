## Overview

Detect stored cross-site scripting attacks in Nginx access logs where malicious scripts are permanently stored on the server. This detection identifies attempts to inject persistent client-side scripts into web pages that will be viewed by other users.

The detection focuses on identifying stored XSS patterns in POST requests and other data submission methods, including script tags, event handlers, and other HTML injection vectors that might be used to execute malicious code in users' browsers.

**References**:
- [OWASP Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 