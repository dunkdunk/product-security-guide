# XPath Injection

### Concept

XPath injection is a vulnerability that occurs when user input is not properly sanitized before being used in an XPath query. XPath is a query language used to navigate and select nodes in an XML document. If user input is directly concatenated into an XPath query without proper validation or sanitization, an attacker can manipulate the query to access unauthorized data or bypass authentication.

### Vulnerable Scenario

Consider a web application that allows users to search for products based on certain criteria. The application constructs an XPath query using user-supplied input to retrieve the matching products from an XML database.

#### Example Code (Vulnerable)

```python
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_products():
    category = request.args.get('category')
    xml_file = 'products.xml'
    
    # Load the XML file
    tree = etree.parse(xml_file)
    
    # Construct the XPath query
    query = f"//product[category='{category}']"
    
    # Execute the XPath query
    results = tree.xpath(query)
    
    # Process the results
    products = []
    for product in results:
        name = product.find('name').text
        price = product.find('price').text
        products.append({'name': name, 'price': price})
    
    return {'products': products}
```

### Explanation

In this example, the web application allows users to search for products based on a category. The user-supplied `category` is directly concatenated into the XPath query without any validation or sanitization.

An attacker can exploit this vulnerability by injecting malicious XPath expressions into the `category` parameter. For example, an attacker can input the following value:

```
' or 1=1 or ''='
```

The resulting XPath query becomes:

```xpath
//product[category='' or 1=1 or ''='']
```

This query will match all product nodes in the XML document because the condition `1=1` is always true. The attacker can access the entire list of products, regardless of their actual category.

Furthermore, an attacker can exploit XPath injection to bypass authentication or access sensitive data by crafting malicious XPath expressions that alter the query's logic.

### Prevention

To prevent XPath injection vulnerabilities, consider the following measures:

1. Validate and sanitize user input: Implement proper input validation and sanitization techniques to ensure that user-supplied data is free from malicious characters and conforms to the expected format.
2. Use parameterized queries: Instead of directly concatenating user input into XPath queries, use parameterized queries or prepared statements to separate the user input from the query structure.
3. Limit user input: Restrict the characters allowed in user input to a whitelist of safe characters, excluding any special characters or metacharacters used in XPath syntax.
4. Apply the principle of least privilege: Ensure that the application's database user has minimal privileges required to perform its intended functions, limiting the potential impact of a successful XPath injection attack.
5. Use secure XML parsing libraries: Utilize secure XML parsing libraries that provide built-in protection against XPath injection and other XML-related vulnerabilities.

#### Example Code (Secure)

```python
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search_products():
    category = request.args.get('category')
    xml_file = 'products.xml'
    
    # Validate and sanitize user input
    if not category.isalnum():
        return {'error': 'Invalid category'}, 400
    
    # Load the XML file
    tree = etree.parse(xml_file)
    
    # Construct the parameterized XPath query
    query = "//product[category=$category]"
    
    # Execute the XPath query with parameter
    results = tree.xpath(query, category=category)
    
    # Process the results
    products = []
    for product in results:
        name = product.find('name').text
        price = product.find('price').text
        products.append({'name': name, 'price': price})
    
    return {'products': products}
```

In the secure example, several improvements have been made:

* User input is validated to ensure it contains only alphanumeric characters, preventing the injection of malicious XPath expressions.
* A parameterized XPath query is used, separating the user input from the query structure. The `category` parameter is passed separately to the `xpath()` function.
* The application checks the validity of the user input before executing the query, reducing the risk of successful XPath injection attacks.

Additionally, it is important to apply the principle of least privilege and use secure XML parsing libraries to further mitigate the risk of XPath injection vulnerabilities.

### Conclusion

XPath injection is a serious vulnerability that can allow attackers to access unauthorized data, bypass authentication, or manipulate the application's behavior by injecting malicious XPath expressions. To prevent XPath injection, it is crucial to validate and sanitize user input, use parameterized queries, limit user input to a whitelist of safe characters, apply the principle of least privilege, and use secure XML parsing libraries. Developers should be cautious when handling user input in XPath queries and follow secure coding practices to mitigate the risk of XPath injection attacks.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: xpath-injection
    patterns:
      - pattern: $XML.xpath("..." + $USERINPUT + "...")
    message: "Potential XPath injection vulnerability. Use parameterized queries or sanitize user input."
    languages:
      - python
    severity: ERROR
```
