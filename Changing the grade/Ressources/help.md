# First Step

There is a page named Survey, it looks suspicious especially with the table on the page to do a vote by choose from 1 to 10 in the grade of an user, but what about changing the grade completely or choose a number out of the range they gave to us?

# What to do

I tried to access the inspect page to check the code source, then i picked the number in the grade, for example after picking the number 1 its code html is:

```
<option value="1">1</option>
```
So i change it to:
```
<option value="11">1</option>
```

After changing it and clicking on 1 i get the flag, cuase it's kind of an error.
