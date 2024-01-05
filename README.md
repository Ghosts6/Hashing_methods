![baner](https://github.com/Ghosts6/Hashing_methods/blob/main/Baner.png)
# Hashing :
hash function is a mathematical algorithm that takes an input  and produces output as a fixed-size string of characters, which is typically a hexadecimal or binary representation. This output is known as the hash value or hash code.
now a days we have differend hashing method like md5 ssha sha-1 sha-256 bcrypt and if we want to rank them based on security: 🥇bcrypt 🥈sha-256 🥉ssha


![hash](https://github.com/Ghosts6/Hashing_methods/blob/main/hash.png)


# bcrypt :
with Buildin function:
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
without buildin function:
```python
import hashlib
import os
import base64
# def for hashing password with bcrypt method without using buildin bcrypt functions
def custom_bcrypt(password, salt_rounds=12):
    salt = os.urandom(16)  # 16 bytes
    if not (4 <= salt_rounds <= 31):
        raise ValueError("Salt rounds must be between 4 and 31 inclusive.")
    salt_rounds = 2**salt_rounds    
    # Hash the password 
    hash_password = hashlib.sha256(password.encode()).digest()
    for _ in range(salt_rounds):
        hash_password = hashlib.sha256(hash_password + salt).digest()   
    # Encode the salt and hashed 
    bcrypt_hash = b"$2b$" + base64.b64encode(salt + hash_password)   
    return bcrypt_hash.decode('utf-8')

password = "my_secure_password"
hash_password = custom_bcrypt(password)
# now we can store password in database or to se result like here print it
print("Hashed Password:", hash_password)
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
# usage:
here we will see an example of using hashing method to secure user data in django project
model.py
```python3
from django.db import models
import bcrypt
# table to sort user data
class User(models.Model):
    username = models.CharField(max_length=100, unique=True)
    password = models.CharField(max_length=256)  

    def set_password(self, password):
        # Hash the password using bcrypt and store the hashed value
        hash_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        self.password = hash_password.decode('utf-8')
        
    def check_password(self, password):
        return bcrypt.checkpw(password.encode(), self.password.encode())
            
    # Automatically hash the password 
    def save(self, *args, **kwargs):
        if not self.pk: 
            self.set_password(self.password)
        super().save(*args, **kwargs)
   
    def __str__(self):
        return self.username
```
# salt:
🧂 salt is a random string of data that is added to the input(password) before the hashing process. The primary purpose of using a salt is to enhance the security of hashed passwords.
Salting helps defend against attacks like precomputed rainbow table attacks. By adding a unique random salt to each password before hashing, even identical passwords will have different hashed values.
Each user's password is hashed with a unique salt. This means if two users have the same password, their hashed passwords in the database will be different due to the unique salts.
Salting increases the complexity of brute-force and dictionary attacks. Attackers need to compute hashes for each password guess combined with each unique salt, significantly increasing the computational effort required to crack passwords.
![salt](https://github.com/Ghosts6/Hashing_methods/blob/main/salt-hash-password.jpg)

# more to read:
if you interested in hashing and password security and how to improve it,its good idea to learn about rainbow table and differed way of using and adding salt 
