# Server-Side Request Forgery (SSRF)

### Concept

Server-Side Request Forgery (SSRF) is a vulnerability that occurs when an application allows users to control or manipulate URLs or requests that the server sends. Attackers can exploit this vulnerability to make the server send requests to unintended or unauthorized destinations, leading to the disclosure of sensitive information, unauthorized access to internal resources, or denial-of-service (DoS) attacks.

### Vulnerable Scenario

Consider a web application that fetches data from a user-supplied URL and displays it to the user. The application does not properly validate or restrict the URL provided by the user, allowing them to manipulate the server's request.

#### Example Code (Vulnerable)

```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch_data():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text
```

### Explanation

In this example, the `/fetch` route accepts a `url` parameter from the user via the query string. The `requests.get()` function is used to send a GET request to the specified URL, and the response text is returned to the user.

An attacker can exploit this vulnerability by providing a crafted URL that points to an internal network resource or a sensitive endpoint. For example:

```
http://example.com/fetch?url=http://internal-service/admin
```

In this case, the attacker manipulates the `url` parameter to point to an internal service (`http://internal-service/admin`) that is not intended to be accessible from outside the network. The server will send a request to this internal service on behalf of the attacker, potentially exposing sensitive information or performing unauthorized actions.

Furthermore, the attacker can use SSRF to scan internal networks, exploit vulnerabilities in internal services, or launch DoS attacks by making the server send requests to slow or unresponsive endpoints.

### Prevention

To prevent Server-Side Request Forgery (SSRF), consider the following measures:

1. Validate and sanitize user-supplied URLs before using them in server-side requests. Ensure that the URL conforms to the expected format and does not contain any malicious or unauthorized components.
2. Implement a whitelist approach to restrict the allowed destinations for server-side requests. Only allow requests to trusted and authorized domains or IP addresses.
3. Avoid using user-supplied URLs directly in server-side requests. Instead, map the user input to predefined endpoints or actions within your application.
4. Use network segmentation and firewall rules to limit the server's ability to send requests to internal or sensitive network resources.
5. Implement proper authentication and authorization mechanisms to ensure that only authorized users can access the functionality that triggers server-side requests.

#### Example Code (Secure)

```python
from flask import Flask, request
import requests

app = Flask(__name__)

ALLOWED_DOMAINS = ['example.com', 'api.example.com']

@app.route('/fetch')
def fetch_data():
    url = request.args.get('url')
    
    # Validate and sanitize the URL
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.netloc not in ALLOWED_DOMAINS:
        return "Unauthorized domain", 403
    
    response = requests.get(url)
    return response.text
```

In the secure example, the `ALLOWED_DOMAINS` list defines the trusted domains that are allowed for server-side requests. The user-supplied URL is parsed using `urllib.parse.urlparse()`, and the domain (netloc) is extracted. If the domain is not in the `ALLOWED_DOMAINS` list, an "Unauthorized domain" error is returned.

By validating and restricting the allowed domains, the application prevents SSRF attacks and ensures that server-side requests are only sent to trusted destinations.

### Conclusion

Server-Side Request Forgery (SSRF) is a critical vulnerability that can allow attackers to manipulate server-side requests, leading to the disclosure of sensitive information, unauthorized access to internal resources, and DoS attacks. To mitigate SSRF, it is crucial to validate and sanitize user-supplied URLs, implement a whitelist approach for allowed destinations, avoid using user-supplied URLs directly, and enforce proper network segmentation and access controls. Developers should be cautious when handling user-controlled URLs and ensure that server-side requests are only sent to trusted and authorized destinations.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: server-side-request-forgery
    patterns:
      - pattern: requests.get(...)
      - pattern-not: requests.get("https://example.com/...")
    message: "Potential Server-Side Request Forgery (SSRF) vulnerability. Ensure proper validation and restriction of user-supplied URLs."
    languages:
      - python
    severity: ERROR
```
