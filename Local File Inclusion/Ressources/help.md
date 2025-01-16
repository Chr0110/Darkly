
## Explanation 

robots.txt is a text file placed on a website's root directory that provides instructions to web robots (also known as web crawlers or spiders) about which parts of the website should or should not be crawled and indexed by search engines. It is used as part of the robots exclusion protocol (REP), a standard used by websites to communicate with web crawlers.

The file is typically used to manage and control the behavior of web crawlers, improving both the performance of a website and its SEO (Search Engine Optimization) strategy.


At http://localhost/robots.txt you get 

```
User-agent: *
Disallow: /whatever
Disallow: /.hidden
```

This tells all bots (User-agent: *) not to crawl or index pages under the /private/ directory.

Then After accessing http://localhost/whatever

```
../
htpasswd                                           29-Jun-2021 18:09                  38
```

the htpasswd file is downloadable and contains:


```
root:437394baff5aa33daa618be47b75cb49
```

This appear to be a pair of login(username and password) and became after cipher identification and decoding:

```
root:qwerty123@
```


Which is the login of the admin interface http://localhost/admin/#

## Securty Measures
Use Secure File Permissions
Configure your server to use least privilege file permissions, ensuring only authorized users and processes have access to sensitive files. For example:
Ensure that files such as /.env, /.git/, and /.gitignore are not exposed to the web.
Restrict the permissions of configuration files and system files such as /etc/passwd to only trusted processes or system users.


Obfuscate or Remove Sensitive Paths
Avoid using common or predictable paths for sensitive pages. For example, don't use /admin/ or /login/ as paths for admin or login pages.
Consider renaming sensitive URLs to make it more difficult for attackers to guess the location of sensitive pages (e.g., change /admin/ to /hidden-admin/).

Use noindex Meta Tags for Sensitive Pages