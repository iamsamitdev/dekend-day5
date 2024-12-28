from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import (
    TokenRefreshView,
)
from .views import InternViewSet, EducationViewSet, TrainingViewSet, WorkExperienceViewSet,RegisterView, LogoutView, LoginView

router = DefaultRouter()
router.register(r'interns', InternViewSet)
router.register(r'educations', EducationViewSet)
router.register(r'trainings', TrainingViewSet)
router.register(r'work-experiences', WorkExperienceViewSet)

urlpatterns = [
    path('auth/register/', RegisterView.as_view(), name='auth_register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='auth_logout'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='auth_refresh'),
    path('', include(router.urls)), # เพิ่มเส้นทางสำหรับการเข้าถึงข้อมูลทั้งหมดของ router
]
