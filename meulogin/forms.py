from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User
from models import RocklabUser
from django.db import models

class SignUpForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('username', 'email', 'password1', 'password2', )

class RocklabUserForm(forms.ModelForm):
    class Meta:
        model = RocklabUser
        fields = ('endereco', 'empresa', )

# class EditProfileForm(forms.ModelForm):
#     class Meta:
#         model = RocklabUser
#         fields = ('endereco', 'empresa', )
