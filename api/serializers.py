from rest_framework import serializers, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Intern, Education, Training, WorkExperience, User

class InternSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(read_only=True, source='user.id')  # เพิ่มฟิลด์นี้ถ้าต้องการให้แสดง user_id ใน response
    class Meta:
        model = Intern
        fields = '__all__'
        read_only_fields = ('user',)  # ป้องกันการแก้ไข user field โดยตรง

class EducationSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(read_only=True, source='user.id')
    class Meta:
        model = Education
        fields = '__all__'
        read_only_fields = ('user',)

class TrainingSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(read_only=True, source='user.id')
    class Meta:
        model = Training
        fields = '__all__'
        read_only_fields = ('user',)

class WorkExperienceSerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(read_only=True, source='user.id')
    class Meta:
        model = WorkExperience
        fields = '__all__'
        read_only_fields = ('user',)

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('username', 'password', 'email', 'first_name', 'last_name', 'tel')
        extra_kwargs = {
            'password': {'write_only': True},
            'email': {'required': True},
            'tel': {'required': False}
        }

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', ''),
            tel=validated_data.get('tel', '')
        )
        return user

class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

class LogoutView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = LogoutSerializer

    def get_serializer(self, *args, **kwargs):
        if getattr(self, 'swagger_fake_view', False):  # ตรวจสอบว่าเป็น Swagger หรือไม่
            return None
        return super().get_serializer(*args, **kwargs)

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = serializer.validated_data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=204)
        except Exception:
            return Response(status=400)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'tel')
        read_only_fields = ('id',)   