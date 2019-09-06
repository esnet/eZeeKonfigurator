# Generated by Django 2.2.4 on 2019-08-30 14:25

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('webconfig', '0005_auto_20190830_0253'),
    ]

    operations = [
        migrations.CreateModel(
            name='Option',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('namespace', models.CharField(default='GLOBAL', max_length=100)),
                ('name', models.CharField(max_length=100)),
                ('datatype', models.CharField(max_length=100)),
                ('docstring', models.CharField(max_length=1000)),
            ],
        ),
        migrations.CreateModel(
            name='Setting',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(max_length=1000)),
                ('option', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='webconfig.Option')),
            ],
        ),
    ]