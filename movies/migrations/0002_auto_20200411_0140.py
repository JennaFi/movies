# Generated by Django 3.0.4 on 2020-04-10 22:40

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('movies', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='movie',
            name='description',
            field=models.TextField(default='Описание', verbose_name='Описание'),
        ),
    ]