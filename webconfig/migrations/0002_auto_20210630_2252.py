# Generated by Django 3.2.4 on 2021-06-30 22:52

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('webconfig', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='BrokerDaemon',
        ),
        migrations.AddField(
            model_name='change',
            name='new_val',
            field=models.CharField(blank=True, max_length=1024, null=True),
        ),
        migrations.AddField(
            model_name='change',
            name='old_val',
            field=models.CharField(blank=True, max_length=1024, null=True),
        ),
        migrations.AlterField(
            model_name='change',
            name='msg',
            field=models.CharField(
                help_text='e.g. Increased timeout due to long-lived connections',
                max_length=1024, verbose_name='Summary of the change'),
        ),
    ]
