## Overview

The XSS Encoded Attack detection identifies Cross-Site Scripting (XSS) attacks that use various encoding techniques to bypass security filters. This is a sophisticated attack vector where attackers encode malicious JavaScript using HTML entities, URL encoding, Unicode encoding, or other obfuscation methods to evade detection.

This detection examines both HTTP requests and User-Agent headers for patterns indicating encoded XSS payloads. It focuses on identifying HTML entity encoding (e.g., `&#x3C;script>`), Base64 encoding, URL encoding, and other encoding schemas that might be used to disguise malicious JavaScript.

Encoded XSS attacks are particularly dangerous because they can bypass many security filters and Web Application Firewalls (WAFs) that only check for literal script tags or JavaScript keywords. By encoding these elements, attackers can create payloads that will be decoded by the browser at runtime but may pass through server-side security controls undetected.

For example, an attacker might encode a script tag as `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`, which appears harmless to basic security filters but will be interpreted as `<script>alert(1)</script>` when rendered by the browser. Similarly, Base64 encoding can be used to completely obscure the contents of a payload until it's decoded and executed.

By examining both request URIs and User-Agent headers, this detection can identify attackers who attempt to evade security controls by hiding their encoded payloads in HTTP headers rather than request parameters. This comprehensive approach helps security teams identify sophisticated XSS attempts that specifically aim to bypass traditional security controls through encoding techniques.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)