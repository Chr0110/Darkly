
# Redirect 

A redirect breach is a type of security vulnerability that occurs when a web application improperly handles URL redirects. This vulnerability can be exploited by an attacker to redirect users from a trusted website to a malicious website without their knowledge, potentially leading to phishing attacks, theft of sensitive information, or other harmful activities.





## Explanation 

When inspecting, social media icons in the footer of a web page use anchor tags with an href attribute to manage redirections. This is what the anchor tag looks like:

```
<a href="index.php?page=redirect&amp;site=instagram" class="icon fa-instagram"></a>
```

Here, the href attribute is pointing to a PHP script index.php with two query parameters:

page=redirect: This likely indicates to the server which page or script to invoke for processing.
site=instagram: This parameter specifies the external destination (in this case, Instagram) to which the user should be redirected.

The vulnerability arises because the redirection parameter (site) is not properly validated by the application. This means that the application does not check if the value of the site parameter is legitimate or malicious. The lack of validation can lead to several security risks:

URL Parameter Tampering: An attacker can modify the site parameter to redirect users to any arbitrary URL. For example, changing site=instagram to site=http://malicious-website.com.

Open Redirect Vulnerability: Since the application does not restrict or validate the URLs to which it will redirect users, it can be misused as an open redirector. This can be exploited in phishing campaigns to increase the trustworthiness of malicious links.


## Attack Execution

Crafting the Malicious URL: An attacker modifies the redirect URL to point to a malicious site:

```
<a href="index.php?page=redirect&site=http://malicious-website.com" class="icon fa-instagram"></a>
```
A user clicks on the Instagram icon in the footer, expecting to visit Instagram’s official page. However, because of the manipulated href, they are redirected to a malicious site.

On the malicious site, the user may be tricked into downloading malware, entering personal information, or performing other actions that compromise their security.



## Prevention and Mitigation Strategies

Validate Redirects: Always validate and sanitize all user inputs, especially those involving redirects. Only allow redirects to a whitelist of approved URLs.
Avoid User-Controlled URLs: If possible, avoid allowing user input to control redirect targets directly. Use indirect methods like mapping inputs to server-side lists of URLs.
Use Security Headers: Implement security headers like Content Security Policy (CSP) to help mitigate the impact of XSS attacks that could be used to inject malicious redirection scripts.
