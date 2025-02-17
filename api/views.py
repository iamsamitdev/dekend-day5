from django.shortcuts import render
from rest_framework import viewsets, generics, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Intern, Education, Training, WorkExperience, User
from .serializers import (
    InternSerializer, EducationSerializer, TrainingSerializer, 
    WorkExperienceSerializer, RegisterSerializer, UserSerializer
)
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.decorators import permission_classes, authentication_classes
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.views import TokenObtainPairView

class InternViewSet(viewsets.ModelViewSet):
    queryset = Intern.objects.all()
    serializer_class = InternSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # กรองข้อมูลตาม user ที่ login
        return Intern.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class EducationViewSet(viewsets.ModelViewSet):
    queryset = Education.objects.all()
    serializer_class = EducationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Education.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class TrainingViewSet(viewsets.ModelViewSet):
    queryset = Training.objects.all()
    serializer_class = TrainingSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return Training.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class WorkExperienceViewSet(viewsets.ModelViewSet):
    queryset = WorkExperience.objects.all()
    serializer_class = WorkExperienceSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return WorkExperience.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['refresh'],
            properties={
                'refresh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Refresh token ที่ได้จากการ login'
                )
            }
        ),
        responses={
            204: 'Logout successful',
            400: 'Bad request - Invalid refresh token'
        },
        operation_description="Logout และเพิ่ม refresh token เข้า blacklist"
    )
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response(
                {"error": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

class LoginView(TokenObtainPairView):
    @swagger_auto_schema(
        responses={
            200: openapi.Response(
                description="Login successful",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'access': openapi.Schema(type=openapi.TYPE_STRING),
                        'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                        'user': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            )
        }
    )
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        token = response.data
        user = User.objects.get(username=request.data['username'])
        user_serializer = UserSerializer(user)
        
        response.data = {
            'access': token['access'],
            'refresh': token['refresh'],
            'user': user_serializer.data
        }
        
        return response            