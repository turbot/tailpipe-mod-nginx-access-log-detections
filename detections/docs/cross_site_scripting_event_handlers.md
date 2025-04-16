## Overview

The XSS Event Handler Attack detection identifies Cross-Site Scripting (XSS) attacks that specifically target HTML event handlers to execute malicious JavaScript. Event handlers like `onload`, `onerror`, and `onclick` can be injected into HTML elements to trigger JavaScript execution when certain browser events occur.

This detection examines both HTTP requests and User-Agent headers for patterns indicating event handler-based XSS attempts. It focuses on identifying both common event handlers that are frequently targeted in XSS attacks and less common event handlers that may be used to evade basic security filters.

Event handler XSS attacks are particularly dangerous because they can bypass traditional XSS filters that focus primarily on script tags. Attackers can inject these event handlers into various HTML elements, creating multiple attack vectors. For example, an attacker might inject `<img src="invalid" onerror="alert(document.cookie)">` into a comment field, causing the malicious JavaScript to execute when the image fails to load.

Modern web applications have numerous event handlers available, and new ones are introduced with each HTML5 specification update. This detection looks for patterns indicating attempts to exploit these event handlers in both request URIs and User-Agent headers, allowing it to catch attackers who attempt to evade detection by hiding their payloads in HTTP headers rather than request parameters.

By monitoring for these event handler patterns, security teams can identify both reconnaissance activities and active exploitation attempts targeting their web applications through this specific XSS vector.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)