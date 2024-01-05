![baner](https://github.com/Ghosts6/Hashing_methods/blob/main/Baner.png)
# Hashing :
hash function is a mathematical algorithm that takes an input  and produces output as a fixed-size string of characters, which is typically a hexadecimal or binary representation. This output is known as the hash value or hash code.
now a days we have differend hashing method like md5 ssha sha-1 sha-256 bcrypt and if we want to rank them based on security: 🥇bcrypt 🥈sha-256 🥉ssha


![hash](https://github.com/Ghosts6/Hashing_methods/blob/main/hash.png)


# bcrypt :
```python
# requirement : pip install bcrypt
import bcrypt
# def for hashing password with bcrypt method
def hash_bcrypt(password):
    hash_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return hash_password
# verify password
def verify_password(hashed, plain):
    return bcrypt.checkpw(plain.encode(), hashed)
password = "my_password"
hash_password = hash_bcrypt(password)
# now we can store password in database or to se result like here print it
print(hash_password)
```
# sha-256 :
```python
import hashlib
# def for hashing password with sha-256 method
def hash_sha_256(password):
    hash_password = hashlib.sha256(password.encode()).hexdigest()
    return hash_password

password = "my_password"
hash_password = hash_sha_256(password)
# now we can store password in database or to se result like here print it
print(hash_password)
```
# ssha/sha-1 :
ssha and sha-1 methods are same the only difference is they add salt to ssha so its more secure then sha-1
```python
import hashlib
import os
# def for hashing password with ssha method
def hash_ssha(password):
    salt = os.urandom(8)
    salted_password = password.encode() + salt
    hash_password = hashlib.sha1(salted_password).digest()
    ssha_password = f'{hash_password.decode("iso-8859-1")}{salt.hex()}'
    return ssha_password

password = "my_password"
hash_password= hash_ssha(password)
# now we can store password in database or to se result like here print it
print(hash_password)
```
# md5 :
And finally we have md5 which is the weakest method and cuz of security issues and bugs its not recommended to use it at all
```python
import hashlib
# def for hashing password with md5 method
def hash_md5(password):
    hash_password = hashlib.md5(password.encode()).hexdigest()
    return hash_password
password = "my_password"
hash_password = hash_md5(password)
# now we can store password in database or to se result like here print it
print(hash_password)
```
# more to read:
if you interested in hashing and password security and how to improve it,its good idea to learn about rainbow table and differed way of using and adding salt 
