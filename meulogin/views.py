# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib.auth.forms import PasswordChangeForm, AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from forms import SignUpForm, RocklabUserForm
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import transaction
from models import RocklabUser

#importes para confirmação por email
from django.http import HttpResponse
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

# Create your views here.
@transaction.atomic
def cadastrar_usuario(request):
    formLogin = AuthenticationForm()
    formCadastro = SignUpForm()
    formUserRocklab = RocklabUserForm()
    if request.method == 'POST':
        print '[views] entrou no POST'
        if 'login' in request.POST:
            username = request.POST['username']
            password = request.POST['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                print 'logou'
                return redirect('/password')
            else:
                messages.error(request, 'Usuário e senha inválidos.')

        elif 'cadastro' in request.POST:
            formCadastro = SignUpForm(request.POST)
            formUserRocklab = RocklabUserForm(request.POST)
            if formCadastro.is_valid() and formUserRocklab.is_valid():
                # formCadastro.save()
                # username = formCadastro.cleaned_data.get('username')
                # raw_password = formCadastro.cleaned_data.get('password1')
                # user = authenticate(username=username, password=raw_password)
                # login(request, user)
                # return redirect('/sucesso')
                user = formCadastro.save(commit=False)
                user.is_active = False
                user.save()

                newRocklabUser = formUserRocklab.save(commit=False)
                # print "===============[voiews] newRocklabUser.empresa",newRocklabUser.empresa

                # fields = list(RocklabUserForm().base_fields)
                # print "===============[voiews] fields ",fields

                for field in list(RocklabUserForm().base_fields):
                    # print "++++++++++++[voiews] field ", field
                    setattr(user.rocklabuser, field, getattr(newRocklabUser, field))
                    user.rocklabuser.save()

                print "[views] +++++++++++ user", user


                # newRocklabUser.user = user
                # print '[views] type(user)', type(user)
                # newRocklabUser.save()
                # print '[views] antes do current site '
                current_site = get_current_site(request)
                mail_subject = 'Activate your account.'
                message = render_to_string('meulogin/acc_active_email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                })

                to_email = formCadastro.cleaned_data.get('email')
                email = EmailMessage(
                    mail_subject, message, to=[to_email]
                )
                print '[views] antes do email send'
                # email.send()
                # print '[views] depois do email send'
                return HttpResponse('Please confirm your email address to complete the registration')

        else:
            print '[views] request.POST',request.POST
    return render(request, "meulogin/index.html", {'formLogin':formLogin, 'formCadastro':formCadastro, 'formUserRocklab':formUserRocklab})

@login_required
def sucesso_cadastrar_usuario(request):
    users = RocklabUser.objects.all()
    return render(request, 'meulogin/sucesso.html', {"users": users})

@login_required
def edit_password(request):
    if request.method == 'POST':
        formChangePassword = PasswordChangeForm(request.user, request.POST)
        print '[views] user', request.user

        if formChangePassword.is_valid():
            user = formChangePassword.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Senha alterada com sucesso.')
            return redirect('/password')
        else:
            messages.error(request, 'Corrija o erro abaixo')
    else:
        formChangePassword = PasswordChangeForm(request.user)

    return render(request, 'meulogin/password.html', {'formChangePassword': formChangePassword})

@login_required
def edit_profile(request):
    formEditProfile = RocklabUserForm()
    if request.method == 'POST':
        formEditProfile = RocklabUserForm(request.POST, instance=request.user.rocklabuser)
        if formEditProfile.is_valid():
            formEditProfile.save()
            messages.success(request, "Dados atualizados com sucesso.")
            return redirect('/sucesso')
        else:
            print '-----------------------[views] formEditProfile.errors', formEditProfile.errors
            messages.error(request, 'Dados inválidos.')
    else:
        return render(request, 'meulogin/edit_profile.html', {'formEditProfile':formEditProfile})

@login_required
def logout_view(request):
    logout(request)
    return redirect('/')

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        # return redirect('home')
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')