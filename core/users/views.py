from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from .models import HalfCoderUser
from .serializers import UserSerializer
import jwt, datetime


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username', None)
        password = request.data.get('password', None)

        if username and password:
            user = HalfCoderUser.objects.filter(username=username).first()
            if user is None:
                raise AuthenticationFailed("User not found")

            if not user.check_password(password):
                raise AuthenticationFailed("Invalid password")

            payload = {
                'id': user.id,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                'iat': datetime.datetime.utcnow()
            }

            token = jwt.encode(payload=payload, key='allelleo', algorithm='HS256')

            respone = Response()
            respone.set_cookie(key='token', value=token, httponly=True)
            respone.data = {
                'token': token
            }
            return respone


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('token', None)
        if not token:
            raise AuthenticationFailed("Unauthenticated")

        try:
            payload = jwt.decode(token, key='allelleo', algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Unauthenticated")

        user = HalfCoderUser.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)

        return Response(serializer.data)


class LogoutView(APIView):
    def post(self, request):
        respone = Response()
        respone.delete_cookie('token')
        respone.data = {
            'message': 'success',
        }
        return respone
