## Overview

Detect cross-site scripting attacks in Nginx access logs that use encoding techniques to bypass security filters. This detection identifies attempts to inject malicious scripts using various encoding methods that might evade traditional input validation.

The detection focuses on identifying encoded XSS patterns, including URL encoding, HTML encoding, Unicode encoding, and other obfuscation techniques that might be used to execute malicious code in users' browsers through Nginx web server requests.

**References**:
- [OWASP Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 