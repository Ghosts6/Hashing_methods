import hashlib
# def for hashing password with sha-256 method
def hash_sha_256(password):
    hash_password = hashlib.sha256(password.encode()).hexdigest()
    return hash_password

password = "my_password"
hash_password = hash_sha_256(password)
# now we can store password in database or to se result like here print it
print(hash_password)