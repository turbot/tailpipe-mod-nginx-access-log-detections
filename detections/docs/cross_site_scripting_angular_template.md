## Overview

The AngularJS Template Injection detection identifies Cross-Site Scripting (XSS) attacks that specifically target AngularJS template expressions. This is a sophisticated attack vector where attackers inject malicious code using AngularJS's template syntax, such as double curly braces (`{{ }}`) and specialized directives.

This detection examines both HTTP requests and User-Agent headers for patterns indicating AngularJS template injection attempts. It focuses on identifying AngularJS-specific syntax and common attack patterns like `{{ constructor.constructor() }}` that can be used to execute arbitrary JavaScript in applications using AngularJS.

AngularJS template injection attacks are particularly dangerous because they can bypass traditional XSS filters that focus on HTML tags and JavaScript syntax. When AngularJS processes templates, it evaluates expressions within curly braces, potentially allowing attackers to execute arbitrary JavaScript if the application doesn't properly sanitize user inputs before incorporating them into templates.

Advanced AngularJS injection techniques often use methods like `$eval` or directives like `ng-init` to execute code. Attackers may also leverage JavaScript's prototype chain to access constructor functions and execute arbitrary code, even in environments with Content Security Policy (CSP) protections.

By examining both request URIs and User-Agent headers, this detection can identify attackers who attempt to evade security controls by hiding their template injection payloads in HTTP headers rather than request parameters. This comprehensive approach helps security teams identify sophisticated AngularJS template injection attempts targeting their web applications.

**References**:
- [OWASP Cross-Site Scripting Prevention](https://owasp.org/www-community/attacks/xss/)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)
