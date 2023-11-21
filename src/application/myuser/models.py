from django.contrib.auth.models import AbstractUser, BaseUserManager

# Create your models here.


class MyUserManager(BaseUserManager):
    """
    Custom user model manager where username is the unique identifiers
    for authentication.
    """
    def create_user(self, username, email, password, **extra_fields):
        """
        Create and save a User with the given username, email and password.
        """
        if not username:
            raise ValueError(('The Username must be set'))
        user = self.model(
            username=username,
            email=self.normalize_email(email),
            **extra_fields
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given username and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(('Superuser must have is_superuser=True.'))
        return self.create_user(username, email, password, **extra_fields)


class MyUser(AbstractUser):
    """
    Custom user model which can be extended by custom fields if needed.
    """
    pass
    # add additional fields in here

    def __str__(self):
        return self.username
