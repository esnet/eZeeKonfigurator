# Generated by Django 2.2.4 on 2019-09-25 18:24

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('webconfig', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='zeektable',
            name='index_types',
            field=models.CharField(default='<unknown>', max_length=1024),
        ),
        migrations.AddField(
            model_name='zeektable',
            name='yield_type',
            field=models.CharField(default='<unknown>', max_length=1024),
        ),
    ]
