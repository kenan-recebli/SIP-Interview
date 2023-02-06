import subprocess

from django.contrib.auth.models import update_last_login
from django.core.cache import cache
from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import CreateModelMixin
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework_simplejwt.authentication import AUTH_HEADER_TYPES
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

from users import serializers
from users.permissions import IsAuthenticated
from users.serializers import UserInfoSerializer


class AuthToken:
    @staticmethod
    def get(credentials):
        serializer = serializers.TokenSerializer(data=credentials)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        data = serializer.validated_data

        serializer.user.tokens.create(hash=data['access'])
        update_last_login(None, serializer.user)

        return Response(data, status.HTTP_200_OK)


class Registration(GenericViewSet, CreateModelMixin):
    serializer_class = serializers.RegisterSerializer

    def create(self, request, *args, **kwargs):
        """
        Create a user.

        :param request:
        :param args:
        :param kwargs:
        :return:
        """
        super().create(request, *args, **kwargs)
        return AuthToken.get(request.data)


class Login(APIView):
    def get_authenticate_header(self, request):
        return f'{AUTH_HEADER_TYPES[0]} realm="api"'

    @staticmethod
    def post(request):
        return AuthToken.get(request.data)


class UserInfo(GenericAPIView):
    permission_classes = [
        IsAuthenticated,
    ]

    serializer_class = UserInfoSerializer

    def get(self, request):
        """
        Get the current user.

        :param request:
        :return:
        """
        return Response(self.get_serializer(request.user).data)

    def put(self, request):
        """
        Get the current user.

        :param request:
        :return:
        """
        serializer = self.get_serializer(request.user, data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({
            'success': not serializer.errors,
        })


class RevokeAuthToken(APIView):
    @staticmethod
    def delete(request):
        """
        Revoke the auth token.

        :param request:
        :return:
        """
        auth_token = request.headers.get('Authorization')
        auth_token = auth_token[7:] if auth_token else None
        if auth_token:
            for token in request.user.tokens.all():
                if token.check_hash(auth_token):
                    token.delete()
            email = request.user.email
            cache.delete(f'has_perm:{email}')
            cache.delete(f'is_staff:{email}')
        return Response(status.HTTP_204_NO_CONTENT)


class Latency(APIView):
    def get(self, request):
        """
        Get the latency.

        :param request:
        :return:
        """
        try:
            result = subprocess.run(
                ['ping', '-c', '1', 'google.com'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            latency_line = [line for line in result.stdout.split('\n') if 'time=' in line][0]
            latency = float(latency_line.split('time=')[1].split(' ms')[0]) / 1000
            response = latency
        except subprocess.CalledProcessError:
            response = None
        return Response(response)
