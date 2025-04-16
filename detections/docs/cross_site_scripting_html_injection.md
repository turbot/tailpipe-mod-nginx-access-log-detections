## Overview

The XSS HTML Injection detection identifies Cross-Site Scripting (XSS) attacks that use HTML tag injection to execute malicious JavaScript. Unlike direct script tag injection, this attack vector leverages various HTML elements with event handlers or specific attributes that can execute JavaScript code.

This detection examines both HTTP requests and User-Agent headers for HTML elements commonly used in XSS attacks, including `<iframe>`, `<img>`, `<svg>`, `<object>`, `<embed>`, as well as HTML5 elements like `<video>` and `<audio>`. These elements can be manipulated to execute JavaScript through event handlers or specialized attributes without requiring explicit script tags.

HTML injection XSS attacks are particularly dangerous because they can bypass many traditional XSS filters that focus primarily on script tags. For example, an attacker might inject an image tag with an onerror event handler: `<img src="invalid" onerror="alert(document.cookie)">`. When the image fails to load, the JavaScript in the event handler executes in the context of the web application.

Modern HTML5 specifications have introduced numerous additional elements and attributes that can be used for XSS attacks, substantially expanding the attack surface. By examining both request URIs and User-Agent headers, this detection can identify attackers who attempt to evade security controls by hiding their payloads in HTTP headers rather than request parameters.

This detection helps security teams identify both reconnaissance activities and active exploitation attempts targeting their web applications through HTML tag-based XSS vectors.

**References**:
- [OWASP XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2021: A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [MITRE ATT&CK: T1059.007 Command and Scripting Interpreter: JavaScript](https://attack.mitre.org/techniques/T1059/007/)