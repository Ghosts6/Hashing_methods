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
