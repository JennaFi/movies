import django_filters.rest_framework
from django.db import models
from django.conf import settings
from django.http import JsonResponse
from rest_framework import generics, permissions, status, views
from django.contrib.auth import login
from rest_framework.response import Response
from rest_framework.views import APIView
from requests.exceptions import HTTPError
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from social_django.utils import load_strategy, load_backend
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import MissingBackend, AuthTokenError, AuthForbidden
from social_django.utils import psa
from django_filters.rest_framework import DjangoFilterBackend
from .models import Movie, Actor
from . import serializers
from .serializers import (
    MovieListSerializer,
    MovieDetailSerializer,
    ReviewCreateSerializer,
    CreateRatingSerializer,
    ActorListSerializer,
    ActorDetailSerializer,
    SocialSerializer,
)
from .service import get_client_ip, MovieFilter


class MovieListView(generics.ListAPIView):

    serializer_class = MovieListSerializer
    filter_backends = (DjangoFilterBackend,)
    filterset_class = MovieFilter
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        movies = Movie.objects.filter(draft=False).annotate(
            rating_user=models.Count(
                "ratings", filter=models.Q(ratings__ip=get_client_ip(self.request)))
        ).annotate(
            middle_star=models.Sum(models.F('ratings__star')) /
            models.Count(models.F('ratings'))

        )
        return movies


class MovieDetailView(generics.RetrieveAPIView):

    queryset = Movie.objects.filter(draft=False)
    serializer_class = MovieDetailSerializer


class ReviewCreateView(generics.CreateAPIView):

    serializer_class = ReviewCreateSerializer


class AddStarRatingView(generics.CreateAPIView):

    serializer_class = CreateRatingSerializer

    def perform_create(self, serializer):
        serializer.save(ip=get_client_ip(self.request))


class ActorsListView(generics.ListAPIView):

    queryset = Actor.objects.all()
    serializer_class = ActorListSerializer


class ActorsDetailView(generics.RetrieveAPIView):

    queryset = Actor.objects.all()
    serializer_class = ActorDetailSerializer


class SocialLoginView(generics.GenericAPIView):
    """Log in using facebook"""
    serializer_class = serializers.SocialSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        """Authenticate user through the provider and access_token"""
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        provider = serializer.data.get('provider', None)
        strategy = load_strategy(request)

        try:
            backend = load_backend(strategy=strategy, name=provider,
                                   redirect_uri=None)

        except MissingBackend:
            return Response({'error': 'Please provide a valid provider'},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            if isinstance(backend, BaseOAuth2):
                access_token = serializer.data.get('access_token')
            user = backend.do_auth(access_token)
        except HTTPError as error:
            return Response({
                "error": {
                    "access_token": "Invalid token",
                    "details": str(error)
                }
            }, status=status.HTTP_400_BAD_REQUEST)
        except AuthTokenError as error:
            return Response({
                "error": "Invalid credentials",
                "details": str(error)
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            authenticated_user = backend.do_auth(access_token, user=user)

        except HTTPError as error:
            return Response({
                "error": "invalid token",
                "details": str(error)
            }, status=status.HTTP_400_BAD_REQUEST)

        except AuthForbidden as error:
            return Response({
                "error": "invalid token",
                "details": str(error)
            }, status=status.HTTP_400_BAD_REQUEST)

        if authenticated_user and authenticated_user.is_active:
            # generate JWT token
            login(request, authenticated_user)
            data = {
                "token": jwt_encode_handler(
                    jwt_payload_handler(user)
                )}
            # customize the response to your needs
            response = {
                "email": authenticated_user.email,
                "username": authenticated_user.username,
                "token": data.get('token')
            }
            return Response(status=status.HTTP_200_OK, data=response)

# class SocialSerializer(serializers.Serializer):
#     """
#     Serializer which accepts an OAuth2 access token.
#     """
#     access_token = serializers.CharField(
#         allow_blank=False,
#         trim_whitespace=True,
#     )
#
#
# @api_view(http_method_names=['POST'])
# @permission_classes([AllowAny])
# @psa()
# def exchange_token(request, backend):
#
#     serializer = SocialSerializer(data=request.data)
#     if serializer.is_valid(raise_exception=True):
#         # set up non-field errors key
#         # http://www.django-rest-framework.org/api-guide/exceptions/#exception-handling-in-rest-framework-views
#         try:
#             nfe = settings.NON_FIELD_ERRORS_KEY
#         except AttributeError:
#             nfe = 'non_field_errors'
#
#         try:
#             # this line, plus the psa decorator above, are all that's necessary to
#             # get and populate a user object for any properly enabled/configured backend
#             # which python-social-auth can handle.
#             user = request.backend.do_auth(serializer.validated_data['access_token'])
#         except HTTPError as e:
#             # An HTTPError bubbled up from the request to the social auth provider.
#             # This happens, at least in Google's case, every time you send a malformed
#             # or incorrect access key.
#             return Response(
#                 {'errors': {
#                     'token': 'Invalid token',
#                     'detail': str(e),
#                 }},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
#
#         if user:
#             if user.is_active:
#                 token, _ = Token.objects.get_or_create(user=user)
#                 return Response({'token': token.key})
#             else:
#                 # user is not active; at some point they deleted their account,
#                 # or were banned by a superuser. They can't just log in with their
#                 # normal credentials anymore, so they can't log in with social
#                 # credentials either.
#                 return Response(
#                     {'errors': {nfe: 'This user account is inactive'}},
#                     status=status.HTTP_400_BAD_REQUEST,
#                 )
#         else:
#             # Unfortunately, PSA swallows any information the backend provider
#             # generated as to why specifically the authentication failed;
#             # this makes it tough to debug except by examining the server logs.
#             return Response(
#                 {'errors': {nfe: "Authentication Failed"}},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )
