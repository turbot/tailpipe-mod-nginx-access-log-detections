## Overview

The XSS Script Tag Vector detection identifies Cross-Site Scripting (XSS) attacks that specifically use script tags to inject and execute arbitrary JavaScript code in the context of a web application. This is one of the most direct and common methods attackers use to exploit XSS vulnerabilities.

This detection examines both HTTP requests and User-Agent headers for standard and obfuscated script tag patterns. It identifies attempts to inject `<script>` tags directly, script tags with external sources, and various evasion techniques attackers use to bypass basic input filters and web application firewalls. These evasion techniques include character splitting, null byte injection, and various encoding methods.

When successful, script tag XSS attacks allow attackers to execute arbitrary JavaScript in the victim's browser, which can lead to session hijacking, credential theft, malicious redirects, or complete account takeover. The injected scripts run with the privileges of the web application, giving attackers access to any information or functionality available to the legitimate application.

The detection helps identify both scanning attempts and active exploitation by focusing on the script tag patterns found in request URIs and User-Agent headers. By examining both the request URI and User-Agent fields, this detection can catch attackers who attempt to evade security controls by placing their payloads in HTTP headers. This approach helps security teams identify potential XSS vulnerabilities in their web applications before they can be successfully exploited, or detect active exploitation attempts.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [PortSwigger: Cross-site scripting](https://portswigger.net/web-security/cross-site-scripting)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)