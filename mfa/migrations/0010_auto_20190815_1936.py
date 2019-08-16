# Generated by Django 2.2.3 on 2019-08-15 18:36

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('mfa', '0009_auto_20190815_1724'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userkey',
            name='key_type',
            field=models.CharField(default='TOTP', max_length=25),
        ),
        migrations.AlterField(
            model_name='userkey',
            name='properties',
            field=django.contrib.postgres.fields.jsonb.JSONField(null=True),
        ),
        migrations.AlterField(
            model_name='userkey',
            name='username',
            field=models.CharField(max_length=250),
        ),
    ]
