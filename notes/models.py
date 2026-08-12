from django.db import models


class AppUser(models.Model):
    """Custom user table (intentionally NOT using Django's built-in auth,
    to demonstrate a realistic crypto-storage mistake some teams make when
    they roll their own auth instead of using django.contrib.auth)."""
    username = models.CharField(max_length=150, unique=True)
    password = models.CharField(max_length=128)  # FLAW 3: plaintext password

    def __str__(self):
        return self.username


class Note(models.Model):
    owner = models.ForeignKey(AppUser, on_delete=models.CASCADE, related_name="notes")
    title = models.CharField(max_length=200)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title
