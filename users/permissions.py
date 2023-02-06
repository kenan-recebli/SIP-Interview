from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from rest_framework import permissions


class IsAuthenticated(permissions.BasePermission):
    """
    Allows access only to authenticated users.
    """

    def has_permission(self, request, view):
        token = request.headers.get('Authorization')
        token = token[7:] if token else None
        user = request.user
        if isinstance(user, AnonymousUser):
            return False
        return cache.get_or_set(f'has_perm:{user.email}', self.check_token(user, token), 86400) if token else False

    def check_token(self, user, auth_token):
        if user and user.is_authenticated:
            for token in user.tokens.order_by('-id'):
                if token.check_hash(auth_token):
                    return True
            return False
        return False
