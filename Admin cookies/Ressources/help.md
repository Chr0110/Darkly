
# Cookies 

When checking the cookies of the application you find a list of values including

```
I_am_admin=68934a3e9455fa72420237eb05902327
admin=false

```

This cookie appears to store sensitive data ( an encoded admin flag or privilege level).
If the encoding is weak (e.g., MD5 without salting), attackers might decode it to escalate privileges.
Attackers can easily modify this value (false to true) using browser developer tools or tools like Burp Suite, gaining unauthorized admin access.

## Exploitation
We determined the hashing algorithm used to create the string with the help of a Cipher Identifier to find out it was MD5
Then we executed a MD5 Decoder to find that the value was false
And same way we encoded 'true' and replaced the value with 

```
I_am_admin=b326b5062b2f0e69046810717534cb09
admin=true

```

## Why is This Important 

Unsecured cookies can compromise user privacy, allow unauthorized actions, and lead to data breaches. Proper cookie management is essential to secure modern web applications.



## Prevention and Mitigation Strategies

Avoid storing critical information (e.g., user roles, access levels) in cookies. Instead, use a server-side session to manage privileges.

Store privilege levels or roles in the server database/session. Any user action should be cross-verified with this data.


Ensure role-based access control (RBAC) is implemented at the server level, not reliant on client-side data.

Add flags like HttpOnly, Secure, and SameSite to limit exposure and misuse.
