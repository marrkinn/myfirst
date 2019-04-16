# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.contrib.auth.forms import PasswordChangeForm, AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import login, authenticate, update_session_auth_hash
from forms import SignUpForm
from django.contrib import messages


# Create your views here.
def cadastrar_usuario(request):
    formLogin = AuthenticationForm()
    formCadastro = SignUpForm()
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
            if formCadastro.is_valid():
                formCadastro.save()
                username = formCadastro.cleaned_data.get('username')
                raw_password = formCadastro.cleaned_data.get('password1')
                user = authenticate(username=username, password=raw_password)
                login(request, user)
                return redirect('/sucesso')

        else:
            print '[views] request.POST',request.POST
    return render(request, "meulogin/index.html", {'formLogin':formLogin, 'formCadastro':formCadastro})

def sucesso_cadastrar_usuario(request):
    users = User.objects.all()
    return render(request, 'meulogin/sucesso.html', {"users": users})

def edit_profile(request):
    if request.method == 'POST':
        formChangePassword = PasswordChangeForm(request.user, request.POST)
        print 'user', request.user

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