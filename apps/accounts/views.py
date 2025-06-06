from datetime import datetime

from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers import serialize

from rest_framework import permissions, status
from rest_framework.decorators import permission_classes
from rest_framework.exceptions import ValidationError, NotFound
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from apps.shared.utility import send_email, check_email_or_phone
from apps.accounts.serializers import (SignUpSerializer, 
                               ChangeUserInformation, 
                               ChangeUserPhotoSerializer, 
                               LoginSerializer, 
                               LoginRefreshSerializer, 
                               LogoutSerializer, 
                               ForgotPasswordSerializer, 
                               ResetPasswordSerializer)
from apps.accounts.models import User, CODE_VERIFIED, NEW, VIA_EMAIL, VIA_PHONE

from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

import time

class CreateUserView(CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = SignUpSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            serializer.save()
            response = {
                "error": None,
                "message": "Foydalanuvchi muvaffaqiyatli yaratildi",
                "timestamp": int(time.time() * 1000),
                "status": 201,
                "path": request.path,
                "data": serializer.to_representation(serializer.instance),
                "response": None
            }
            return Response(response, status=status.HTTP_201_CREATED)
        else:
            response = {
                "error": serializer.errors,
                "message": "Foydalanuvchi yaratishda xatolik",
                "timestamp": int(time.time() * 1000),
                "status": 400,
                "path": request.path,
                "data": None,
                "response": None
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)

class VerifyEmailView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'code': openapi.Schema(type=openapi.TYPE_STRING, description='Verification code')
            },
            required=['code']
        ),
        responses={200: "Verification successful"}
    )
    def post(self, request, *args, **kwargs):
        
        code = request.data.get('code')
        if not code:
            error_response = {
                "error": "MissingField",
                "message": "code: This field is required.",
                "timestamp": int(time.time() * 1000),
                "status": 400,
                "path": request.path,
                "data": None,
                "response": None
            }
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)
            
        user = request.user
        success, error_type, error_message = self.check_verify(user, code)
        if success:
            resonse = {
                "error": None,
                "message": "Tasdiqlash kodingiz muvaffaqiyatli qabul qilindi",
                "timestamp": int(time.time() * 1000),
                "status": 200,
                "path": request.path,
                "data": {
                    "id": user.id
                },
                "response": None
            }
            return Response(resonse, status=status.HTTP_200_OK)
        else:
            error_response = {
                "error": error_type,
                "message": error_message,
                "timestamp": int(time.time() * 1000),
                "status": 400,
                "path": request.path,
                "data": None,
                "response": None
            }
            return Response(error_response, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def check_verify(user, code):
        verifies = user.verify_codes.filter(
            expiration_time__gte=datetime.now(), 
            code=code, 
            is_confirmed=False)
        
        if not verifies.exists():
            return False, "InvalidCode", "Tasdiqlash kodingiz xato yoki eskirgan"
        else:
            verifies.update(is_confirmed=True)

            if user.auth_status == NEW:
                user.auth_status = CODE_VERIFIED
                user.save()
            return True, None, None


class GetNewVerification(APIView):
    permission_classes = [permissions.IsAuthenticated,]

    def get(self, request, *args, **kwargs):
        user = self.request.user
        success, message = self.check_verification(user)
        if success:
            response_data = {
                "error": None,
                "message": message,
                "timestamp": int(time.time() * 1000),
                "status": 400,
                "path": request.path,
                "data": None,
                "response": None
            }
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        
        if user.auth_status == VIA_EMAIL:
            code = user.create_verify_code(VIA_EMAIL)
            send_email(user.email, code)
        elif user.auth_type == VIA_PHONE:
            code = user.create_verify_code(VIA_PHONE)
            send_email(user.phone_number, code)
        else:
            response_data = {
                "error": None,
                "message": "Email yoki telefon raqami noto'g'ri",
                "timestamp": int(time.time() * 1000),
                "status": 400,
                "path": request.path,
                "data": None,
                "response": None
            }
            return Response(response_data, status=status.HTTP_400_BAD_REQUEST)
        response_data = {
            "error": None,
            "message": "Tasdiqlash kodi muvaffaqiyatli yuborildi",
            "timestamp": int(time.time() * 1000),
            "status": 200,
            "path": request.path,
            "data": None,
            "response": None
        }
        return response_data

    @staticmethod
    def check_verification(user):
        verifies = user.verify_codes.filter(expiration_time__gte=datetime.now(), is_confirmed=False)
        if verifies.exists():
            return True, "Kodingiz hali ishlatish uchun yaroqli, Biroz kutib turing"


class ChangeUserInformationView(UpdateAPIView):
    permission_classes = [permissions.IsAuthenticated,]
    serializer_class = ChangeUserInformation
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user
    
    def get_response_data(self, request):
        user = self.get_object()
        return {
            "error": None,
            "message": "User updated successfully",
            "timestamp": int(time.time() * 1000),
            "status": 200,
            "path": request.path,
            "data": {
                "id": user.id
            },
            "response": None
        }

    def partial_update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).partial_update(request, *args, **kwargs)
        return Response(self.get_response_data(request=request), status=200)
    def update(self, request, *args, **kwargs):
        super(ChangeUserInformationView, self).update(request, *args, **kwargs)
        return Response(self.get_response_data(request=request), status=200)


class ChangeUserPhotoView(APIView):
    permission_classes = [IsAuthenticated, ]

    def put(self, request, *args, **kwargs):
        serializer = ChangeUserPhotoSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            serializer.update(user, serializer.validated_data)
            return Response(
                {
                    "message": "Rasm muvaffaqiyatliy o'zgartirildi"
                },
                status=status.HTTP_200_OK
            )


class LoginView(TokenObtainPairView):
    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data
            user = serializer.user

            return Response({
                "error": None,
                "message": "Logged in successfully",
                "timestamp": int(time.time() * 1000),
                "status": 200,
                "path": request.path,
                "data": {
                    "access_token": validated_data.get('access'),
                    "refresh_token": validated_data.get('refresh_token'),
                    "full_name": user.full_name,
                },
                "response": None
            },
                status=status.HTTP_200_OK
            )
        except ValidationError as e:
            return Response(
                {
                    "error": "InvalidCredentials",
                    "message": "Invalid credentials",
                    "timestamp": int(time.time() * 1000),
                    "status": 400,
                    "path": request.path,
                    "data": None,
                    "response": None
                },
                status=status.HTTP_400_BAD_REQUEST
            )


class LoginRefreshView(TokenRefreshView):
    serializer_class = LoginRefreshSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        
        try:
            serializer.is_valid(raise_exception=True)
            validated_data = serializer.validated_data
            print(validated_data)
            return Response({
                "error": None,
                "message": "Token refreshed successfully",
                "timestamp": int(time.time() * 1000),
                "status": 200,
                "path": request.path,
                "data": {
                    "access_token": validated_data.get('access'),
                    "refresh_token": validated_data.get('refresh')
                },
                "response": None
            },
                status=status.HTTP_200_OK
            )

        except ValidationError as e:
            return Response(
                {
                    "error": "InvalidCredentials",
                    "message": "Invalid credentials",
                    "timestamp": int(time.time() * 1000),
                    "status": 400,
                    "path": request.path,
                    "data": None,
                    "response": None
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        




class LogOutView(APIView):
    serializer_class = LogoutSerializer
    permission_classes = [IsAuthenticated]

    def get_response_structure(self, error=None, message=None, status_code=200, data=None, response_data=None):
        """Javob strukturasini shakllantirish uchun yordamchi metod"""
        return Response(
            {
                "error": error,
                "message": message,
                "timestamp": int(time.time() * 1000),
                "status": status_code,
                "path": self.request.path,
                "data": data,
                "response": response_data
            },
            status=status_code
        )
    @swagger_auto_schema(
        operation_description="Foydalanuvchini tizimdan chiqarish uchun endpoint. Refresh tokenni yuborish talab qilinadi.",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(
                    type=openapi.TYPE_STRING,  # Bu yerda Concurrent o'rniga TYPE_STRING ishlatildi
                    description='Foydalanuvchining refresh tokeni'
                ),
            },
        ),
        responses={
            200: openapi.Response(
                description="Muvaffaqiyatli logout",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING, nullable=True),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'timestamp': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'status': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'path': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True),
                        'response': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True),
                    }
                )
            ),
            400: openapi.Response(
                description="Noto'g'ri so'rov",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'timestamp': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'status': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'path': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True),
                        'response': openapi.Schema(type=openapi.TYPE_OBJECT, nullable=True),
                    }
                )
            ),
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if not serializer.is_valid():
            return self.get_response_structure(
                error="InvalidData",
                message="Invalid or missing refresh token",
                status_code=status.HTTP_400_BAD_REQUEST,
                data=serializer.errors
            )

        refresh_token = serializer.validated_data['refresh']
        token = RefreshToken(refresh_token)
        token.blacklist()

        return self.get_response_structure(
            error=None,
            message="Logged out successfully",
            status_code=status.HTTP_200_OK
        )



class ForgotPasswordView(APIView):
    permission_classes = [AllowAny, ]
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email_or_phone = serializer.validated_data['email_or_phone']
        user = serializer.validated_data.get('user')
        if check_email_or_phone(email_or_phone) == 'phone':
            code = user.create_verify_code(VIA_PHONE)
            send_email(email_or_phone, code)
        elif check_email_or_phone(email_or_phone) == 'email':
            code = user.create_verify_code(VIA_EMAIL)
            send_email(email_or_phone, code)

        return Response(
            {
                "success": True,
                "message": "Tasdiqlash kodi muvaffaqiyatliy yuborildi",
                "access": user.token()['access'],
                "refresh": user.token()['refresh'],
                "user_status": user.auth_status,
            }, status=status.HTTP_200_OK
        )


class ResetPasswordView(UpdateAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ['patch', 'put']

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        # Boshlang‘ich qiymatlar
        error = None
        message = None
        status_code = status.HTTP_200_OK
        data = None

        try:
            # Serializer orqali yangilash
            super(ResetPasswordView, self).update(request, *args, **kwargs)
            user = self.request.user  # Joriy foydalanuvchi
            message = "Parolingiz muvaffaqiyatli o'zgartirildi"
            data = {
                "id": str(user.id),  # Foydalanuvchi ID sini qo‘shish
                "access": user.token()['access'],
                "refresh": user.token()['refresh_token'],
            }

        except ValidationError as e:
            error = "ValidationError"
            message = str(e.detail) if e.detail else "Ma’lumotlar noto‘g‘ri kiritildi"
            status_code = status.HTTP_400_BAD_REQUEST
        except ObjectDoesNotExist as e:
            error = "NotFound"
            message = str(e)
            status_code = status.HTTP_404_NOT_FOUND
        except Exception as e:
            error = type(e).__name__
            message = str(e) or "Noma’lum xatolik yuz berdi"
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR

        # Har qanday holatda ham bir xil formatda javob qaytarish, response har doim null
        return Response(
            {
                "error": error,
                "message": message,
                "timestamp": int(time.time() * 1000),
                "status": status_code,
                "path": self.request.path,
                "data": data,
                "response": None  # Doim null qaytadi
            },
            status=status_code
        )