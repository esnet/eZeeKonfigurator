# Generated by Django 3.2.4 on 2021-07-01 00:32

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('webconfig', '0004_alter_zeekport_proto'),
    ]

    operations = [
        migrations.AlterField(
            model_name='zeekport',
            name='proto',
            field=models.CharField(
                choices=[('t', 'tcp'), ('u', 'udp'), ('i', 'icmp'),
                         ('?', 'unknown')], default='?', max_length=1),
        ),
    ]
