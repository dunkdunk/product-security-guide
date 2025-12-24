# XML External Entity (XXE) Injection

### Concept

XML External Entity (XXE) Injection is a vulnerability that occurs when an application parses untrusted XML input without proper defenses. Attackers can exploit this vulnerability to include external entities in the XML document, leading to the disclosure of sensitive data, server-side request forgery (SSRF), or denial-of-service (DoS) attacks.

### Vulnerable Scenario

Consider a web application that accepts XML input from users and processes it using an XML parser that supports external entities. The application does not disable external entity resolution or validate the XML input properly.

#### Example Code (Vulnerable)

```python
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    parser = etree.XMLParser()
    tree = etree.fromstring(xml_data, parser)
    # Process the parsed XML data
    # ...
    return "XML parsed successfully"
```

### Explanation

In this example, the `/parse` route accepts XML data from the user via a POST request. The `etree.XMLParser()` is used to create an XML parser, and the `etree.fromstring()` function is used to parse the XML data.

An attacker can exploit this vulnerability by crafting a malicious XML payload that includes an external entity reference. For example:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

In this payload, the attacker defines an external entity named `xxe` that references the `/etc/passwd` file on the server. When the application parses this XML, the external entity is resolved, and the contents of the `/etc/passwd` file are included in the parsed XML data.

The attacker can then retrieve sensitive information, such as system files, by referencing the external entity in the XML payload. Additionally, the attacker can use external entities to perform SSRF attacks by referencing internal network resources or conduct DoS attacks by including large files or recursive entities.

### Prevention

To prevent XML External Entity (XXE) Injection, consider the following measures:

1. Disable external entity resolution in the XML parser configuration. In Python, you can use the `resolve_entities` parameter in the `etree.XMLParser()` constructor and set it to `False`.
2. Validate and sanitize XML input before parsing it. Ensure that the XML input conforms to the expected structure and does not contain any malicious or unexpected elements.
3. Use a whitelist approach to restrict the allowed XML elements, attributes, and entities based on your application's requirements.
4. Keep the XML parser and any associated libraries up to date with the latest security patches.
5. Consider using less complex data formats, such as JSON, if your application does not require the full functionality of XML.

#### Example Code (Secure)

```python
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/parse', methods=['POST'])
def parse_xml():
    xml_data = request.get_data()
    parser = etree.XMLParser(resolve_entities=False)
    try:
        tree = etree.fromstring(xml_data, parser)
        # Process the parsed XML data
        # ...
        return "XML parsed successfully"
    except etree.XMLSyntaxError:
        return "Invalid XML", 400
```

In the secure example, the `resolve_entities` parameter is set to `False` when creating the XML parser, disabling the resolution of external entities. Additionally, the XML input is parsed inside a try-except block to handle any XML syntax errors gracefully.

### Conclusion

XML External Entity (XXE) Injection is a serious vulnerability that can lead to the disclosure of sensitive information, SSRF attacks, and DoS attacks. To mitigate XXE, it is essential to disable external entity resolution in XML parsers, validate and sanitize XML input, use a whitelist approach for allowed elements and entities, and keep XML parsers and libraries up to date. Developers should exercise caution when processing untrusted XML input and take appropriate measures to prevent XXE attacks.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: xxe-injection
    patterns:
      - pattern: etree.fromstring(..., etree.XMLParser())
    message: "Potential XML External Entity (XXE) Injection vulnerability. Ensure external entity resolution is disabled."
    languages:
      - python
    severity: ERROR
```
