## Overview

Detect DOM-based cross-site scripting attacks in Nginx access logs that manipulate the Document Object Model. This detection identifies attempts to inject malicious scripts through client-side DOM manipulation rather than server-side injection.

The detection focuses on identifying DOM manipulation patterns, including document.write, innerHTML, and other DOM manipulation methods that might be used to execute malicious code in users' browsers. It also looks for URL fragment patterns that could be used in DOM-based XSS attacks.

**References**:
- [OWASP Cross-Site Scripting (XSS)](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [MITRE ATT&CK: Exploit Public-Facing Application (T1190)](https://attack.mitre.org/techniques/T1190/) 