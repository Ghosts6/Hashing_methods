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
