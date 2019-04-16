from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    endereco = forms.CharField(max_length=100, required=False)
    empresa = forms.CharField(max_length=30, required=False)

    class Meta:
        model = User
        fields = ('username', 'endereco', 'empresa', 'password1', 'password2', )

class UpdateProfile(UserChangeForm):
    endereco = forms.CharField(max_length=100, required=False)
    empresa = forms.CharField(max_length=30, required=False)

    class Meta:
        model = User
        fields = ('username', 'endereco', 'empresa', )
