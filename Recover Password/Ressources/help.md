
## Explanation 


at http://localhost/?page=recover# which is the page of forgotten password. you need to submit  a request to the admin. the form inludes a hidden input which is the following: 

<input type="hidden" name="mail" value="webmaster@borntosec.com" maxlength="15">

The fact of replacing the mail value is can cause sending  the mail to the wrong destination.


##  Security Implications

Since hidden input fields are stored in the HTML source code, they are accessible to anyone who inspects the page's source code (e.g., through the browser's developer tools). Attackers or users can modify the hidden field's value before submitting the form.

 If the server does not properly validate the hidden input fields when the form is submitted, attackers can craft requests that bypass certain checks or submit malicious data.


 ## Mitigation Measures


 Do not store sensitive information (such as email addresses, session tokens, user credentials, etc.) in hidden fields, as this data can be easily manipulated or intercepted. Instead, consider using secure sessions or server-side storage to handle sensitive data.


To prevent attackers from tampering with the hidden input fields, Cross-Site Request Forgery (CSRF) protection should be implemented. CSRF tokens should be included in the form and validated on the server to ensure that requests are coming from legitimate users.