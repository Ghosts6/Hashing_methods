import hashlib
# def for hashing password with md5 method
def hash_md5(password):
    hash_password = hashlib.md5(password.encode()).hexdigest()
    return hash_password
password = "my_password"
hash_password = hash_md5(password)
# now we can store password in database or to se result like here print it
print(hash_password) 