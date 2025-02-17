# Generated by Django 5.1.3 on 2025-02-17 10:02

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0002_intern_position_interest_intern_position_type_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='education',
            name='user',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='education_profile', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='training',
            name='user',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='training_profile', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AlterField(
            model_name='workexperience',
            name='user',
            field=models.OneToOneField(null=True, on_delete=django.db.models.deletion.CASCADE, related_name='work_experience_profile', to=settings.AUTH_USER_MODEL),
        ),
    ]
