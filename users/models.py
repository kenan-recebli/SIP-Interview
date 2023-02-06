from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.db import models


class User(AbstractUser):
    phone = models.CharField(max_length=15, null=True, unique=True)
    groups = models.ManyToManyField(Group, blank=True, related_name='users')
    user_permissions = models.ManyToManyField(Permission, blank=True, related_name='users')


class Token(models.Model):
    id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(User, models.CASCADE, db_index=True, related_name='tokens')
    hash = models.CharField(max_length=88)

    class Meta:
        default_permissions = ()

    def set_hash(self, token):
        """
        Hash the token.

        :param token:
        :return:
        """
        self.hash = make_password(token)

    def check_hash(self, raw_hash):
        """
        Return a boolean of whether the raw_hash was correct. Handles
        hashing formats behind the scenes.

        :param raw_hash:
        :return:
        """

        def setter(token):
            self.set_hash(token)
            self.save(update_fields=['hash'])

        return check_password(raw_hash, self.hash, setter)

    def save(self, **kwargs):
        self.set_hash(self.hash)
        super().save(**kwargs)
