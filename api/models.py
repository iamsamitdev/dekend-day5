from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    tel = models.CharField(max_length=15, blank=True)

    class Meta:
        db_table = 'auth_user'

class Intern(models.Model):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    gender = models.CharField(max_length=10)
    birth_date = models.DateField()
    nationality = models.CharField(max_length=50, blank=True)
    religion = models.CharField(max_length=50, blank=True)
    weight = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    height = models.DecimalField(max_digits=5, decimal_places=2, blank=True, null=True)
    english_level = models.CharField(max_length=20, blank=True)
    skills = models.TextField(blank=True)
    phone_number = models.CharField(max_length=15)
    email = models.EmailField(unique=True)
    address = models.TextField(blank=True)
    province = models.CharField(max_length=50, blank=True)
    district = models.CharField(max_length=50, blank=True)
    zipcode = models.CharField(max_length=10, blank=True)
    profile_picture = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'interns'

class Education(models.Model):
    user = models.ForeignKey(Intern, on_delete=models.CASCADE)
    level = models.CharField(max_length=50)
    institution_name = models.CharField(max_length=100)
    faculty = models.CharField(max_length=100, blank=True)
    field_of_study = models.CharField(max_length=100, blank=True)
    gpa = models.DecimalField(max_digits=3, decimal_places=2, blank=True, null=True)
    status = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'education'

class Training(models.Model):
    user = models.ForeignKey(Intern, on_delete=models.CASCADE)
    topic = models.CharField(max_length=100)
    details = models.TextField(blank=True)
    trainer = models.CharField(max_length=100, blank=True)
    training_date = models.DateField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'trainings'

class WorkExperience(models.Model):
    user = models.ForeignKey(Intern, on_delete=models.CASCADE)
    position = models.CharField(max_length=100)
    company_name = models.CharField(max_length=100)
    job_description = models.TextField(blank=True)
    start_date = models.DateField()
    end_date = models.DateField(blank=True, null=True)
    is_current = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'work_experiences'

