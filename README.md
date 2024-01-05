![baner](https://github.com/Ghosts6/Hashing_methods/blob/main/Baner.png)
# Hashing :
hash function is a mathematical algorithm that takes an input  and produces output as a fixed-size string of characters, which is typically a hexadecimal or binary representation. This output is known as the hash value or hash code.
now a days we have differend hashing method like md5 ssha sha-1 sha-256 bcrypt and if we want to rank them based on security: 🥇bcrypt 🥈sha-256 🥉ssha  
# bycrypt :
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

# ssha :

# sha-1 :

# md5 :
