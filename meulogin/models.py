from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

class RocklabUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    endereco = models.CharField(max_length=100, blank=True, null=True)
    empresa = models.CharField(max_length=30, blank=True, null=True)

    class Meta:
        abstract = False
        db_table='rocklabuser'

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        RocklabUser.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.rocklabuser.save()
