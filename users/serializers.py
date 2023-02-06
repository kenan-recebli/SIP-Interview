from django.contrib.auth.models import update_last_login
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken

from users.models import User


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)
    confirm = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'email',
            'phone',
            'password',
            'confirm',
        ]

    def validate(self, attrs):
        """
        Validate the serializer.

        :param attrs:
        :return:
        """
        if attrs['confirm'] != attrs['password']:
            raise serializers.ValidationError({
                'confirm': _('Passwords must be the same.'),
            })
        return attrs

    def create(self, validated_data):
        """
        Create a new object.

        :param validated_data:
        :return:
        """
        password = validated_data['password']

        del validated_data['password']
        del validated_data['confirm']

        user = super().create(validated_data)
        user.set_password(password)
        user.save()
        return user


class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            'id',
            'email',
            'username',
            'phone',
            'date_joined',
        ]


class TokenSerializer(TokenObtainSerializer):  # noqa
    @classmethod
    def get_token(cls, user):
        return RefreshToken.for_user(user)

    def validate(self, attrs):
        data = super().validate(attrs)
        refresh = self.get_token(self.user)

        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)

        if api_settings.UPDATE_LAST_LOGIN:
            update_last_login(None, self.user)

        return data
