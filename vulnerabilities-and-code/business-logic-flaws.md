# Business Logic Flaws

### Concept

Business logic flaws are vulnerabilities that occur when the application's business rules and logic are improperly implemented or can be manipulated by attackers. These flaws allow attackers to exploit the application's functionality in unintended ways to gain unauthorized access, bypass restrictions, or perform fraudulent activities.

### Vulnerable Scenario

Consider an e-commerce application that applies discounts to user orders based on certain conditions. The application's business logic calculates the discount amount and applies it to the order total.

#### Example Code (Vulnerable)

```python
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/apply-discount', methods=['POST'])
def apply_discount():
    product_id = request.form['product_id']
    quantity = int(request.form['quantity'])
    
    product = get_product_by_id(product_id)
    total_price = product['price'] * quantity
    
    if total_price > 100:
        discount_percentage = 0.1
    elif total_price > 50:
        discount_percentage = 0.05
    else:
        discount_percentage = 0
    
    discount_amount = total_price * discount_percentage
    discounted_price = total_price - discount_amount
    
    session['cart']['total_price'] = discounted_price
    
    return 'Discount applied successfully'
```

### Explanation

In this example, the e-commerce application applies discounts to user orders based on the total price. If the total price exceeds certain thresholds, a corresponding discount percentage is applied to calculate the discounted price.

However, the application's business logic is flawed and can be manipulated by an attacker. The attacker can exploit this vulnerability in the following ways:

1. Manipulating the `quantity` parameter: An attacker can submit a negative or extremely large value for the `quantity` parameter, leading to unintended discounts or even negative prices.
2. Bypassing discount thresholds: An attacker can manipulate the `product_id` or `quantity` parameters to artificially inflate the total price and qualify for higher discount percentages.
3. Tampering with the session data: If the session data is not properly secured, an attacker can modify the `total_price` stored in the session to apply arbitrary discounts to their order.

These business logic flaws can result in financial losses for the application owner and unfair advantages for the attacker.

### Prevention

To prevent business logic flaws, consider the following measures:

1. Validate and sanitize user input: Implement proper input validation and sanitization techniques to ensure that user-supplied data is within expected ranges and does not contain malicious or unexpected values.
2. Implement server-side validation: Perform all critical business logic validations and calculations on the server-side, rather than relying solely on client-side validation.
3. Use secure session management: Implement secure session management practices to prevent tampering with session data and ensure the integrity of stored values.
4. Conduct thorough testing: Perform comprehensive testing of the application's business logic, including edge cases and unexpected scenarios, to identify and fix vulnerabilities.
5. Implement access controls: Enforce appropriate access controls and permissions to restrict users from accessing or manipulating sensitive business logic.
6. Monitor and log activities: Implement monitoring and logging mechanisms to detect and investigate suspicious activities or anomalies in the application's business logic.

#### Example Code (Secure)

```python
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'your-secret-key'

@app.route('/apply-discount', methods=['POST'])
def apply_discount():
    product_id = request.form['product_id']
    quantity = int(request.form['quantity'])
    
    # Validate and sanitize user input
    if quantity <= 0:
        return 'Invalid quantity', 400
    
    product = get_product_by_id(product_id)
    total_price = product['price'] * quantity
    
    # Calculate discount based on business rules
    if total_price > 100:
        discount_percentage = 0.1
    elif total_price > 50:
        discount_percentage = 0.05
    else:
        discount_percentage = 0
    
    discount_amount = total_price * discount_percentage
    discounted_price = total_price - discount_amount
    
    # Store the discounted price securely in the session
    session['cart']['total_price'] = discounted_price
    
    return 'Discount applied successfully'
```

In the secure example, several improvements have been made:

* User input is validated and sanitized to ensure that the `quantity` is a positive value.
* The discount calculation is performed on the server-side based on the validated total price.
* The discounted price is stored securely in the session to prevent tampering.

Additionally, it is important to conduct thorough testing, implement access controls, and monitor activities to identify and mitigate business logic flaws.

### Conclusion

Business logic flaws can lead to significant vulnerabilities in applications, allowing attackers to exploit the application's functionality for unauthorized access, fraudulent activities, or financial gain. To prevent these flaws, it is crucial to validate and sanitize user input, perform server-side validation, use secure session management, conduct thorough testing, implement access controls, and monitor activities. Developers should carefully design and implement the application's business logic, considering potential loopholes and vulnerabilities, and regularly review and update the logic to ensure its integrity and security.

#### **Semgrep Rule**

This Semgrep rule can be used as a starting point to potentially identify this type of vulnerability.

```yaml
rules:
  - id: business-logic-flaw
    patterns:
      - pattern: |
          $PRICE = $PRODUCT['price'] * $QUANTITY
          ...
          $DISCOUNTED_PRICE = $PRICE - ($PRICE * $DISCOUNT_PERCENTAGE)
      - metavariable-regex:
          metavariable: $QUANTITY
          regex: (?i)(request\.(form|args|cookies|headers))
    message: "Potential business logic flaw. Ensure proper validation and sanitization of user input used in business logic calculations."
    languages:
      - python
    severity: WARNING
```
