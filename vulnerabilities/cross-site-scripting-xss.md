# Cross-Site Scripting (XSS)

### Concept

Cross-Site Scripting (XSS) is a type of web application vulnerability that allows attackers to inject malicious scripts into web pages viewed by other users. XSS vulnerabilities occur when user input is not properly sanitized or validated before being rendered in the browser. Attackers can exploit XSS to steal sensitive information, perform unauthorized actions, or deface websites.

### Vulnerable Scenario

Suppose a web application allows users to post comments on a blog. The application takes the user input and directly inserts it into the HTML page without proper sanitization.

#### Example Code (Vulnerable)

```python
@app.route('/post_comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    # Store the comment in the database
    database.execute("INSERT INTO comments (text) VALUES (?)", (comment,))
    return redirect('/blog')

@app.route('/blog')
def blog():
    comments = database.execute("SELECT * FROM comments")
    return render_template('blog.html', comments=comments)
```

```html
<!-- blog.html -->
<h1>Blog Comments</h1>

<div data-gb-custom-block data-tag="for">


  <div class="comment">
    {{ comment.text | safe }}
  </div>

</div>


```

### Explanation

In this example, the user input for the comment is directly inserted into the database without any sanitization. When rendering the blog page, the comments are retrieved from the database and displayed using the `{{ comment.text | safe }}` syntax, which tells the template engine to render the content as-is, without escaping HTML entities.

If an attacker submits a comment containing malicious JavaScript code, such as `<script>alert('XSS Attack');</script>`, the script will be executed in the browser of any user who views the blog page. The attacker can use this vulnerability to steal session cookies, perform unauthorized actions, or redirect users to malicious websites.

### Prevention

To prevent Cross-Site Scripting (XSS), consider the following measures:

1. Always sanitize and validate user input before rendering it in the browser. Use appropriate escaping mechanisms to convert special characters into their HTML entity equivalents.
2. Implement a Content Security Policy (CSP) to restrict the sources of executable scripts and limit the potential impact of XSS attacks.
3. Use secure templating engines that automatically escape user-supplied data by default.
4. Apply the principle of least privilege and limit the access and capabilities of user-supplied content.

#### Example Code (Secure)

```python
@app.route('/post_comment', methods=['POST'])
def post_comment():
    comment = request.form['comment']
    # Sanitize the comment
    sanitized_comment = sanitize_html(comment)
    # Store the sanitized comment in the database
    database.execute("INSERT INTO comments (text) VALUES (?)", (sanitized_comment,))
    return redirect('/blog')

@app.route('/blog')
def blog():
    comments = database.execute("SELECT * FROM comments")
    return render_template('blog.html', comments=comments)
```

```html
<!-- blog.html -->
<h1>Blog Comments</h1>

<div data-gb-custom-block data-tag="for">


  <div class="comment">
    {{ comment.text }}
  </div>

</div>
```

In the secure example, the user input is sanitized using a secure HTML sanitization library (`sanitize_html`) before storing it in the database. The sanitization process removes or encodes any HTML tags and special characters that could be used for XSS attacks.

When rendering the blog page, the comments are displayed using `{{ comment.text }}` without the `| safe` filter, ensuring that the content is automatically escaped by the templating engine.

### Conclusion

Cross-Site Scripting (XSS) is a prevalent web application vulnerability that can have serious consequences if not properly addressed. Developers must be vigilant in sanitizing and validating user input, implementing secure coding practices, and using appropriate escaping mechanisms to prevent XSS attacks. Regular security testing and keeping frameworks and libraries up to date are also essential to maintain the security of web applications.



#### Semgrep Rule

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: xss-vulnerability
    patterns:
      - pattern: $RESPONSE.send($INPUT)
      - pattern-not: $RESPONSE.send(escape($INPUT))
    message: "Potential XSS vulnerability. Ensure user input is properly sanitized before rendering."
    languages:
      - python
    severity: ERROR
```
