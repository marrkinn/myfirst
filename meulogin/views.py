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
from django.core.mail import EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from .tokens import account_activation_token
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from django.template.loader import get_template

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

            #Formularios de cadastro dos dados do usuario
            formCadastro = SignUpForm(request.POST)
            formUserRocklab = RocklabUserForm(request.POST)

            # Validando os valores dos campos do form
            if formCadastro.is_valid() and formUserRocklab.is_valid():

                #Travando user para futura validacao por email
                user = formCadastro.save(commit=False)
                user.is_active = False
                user.save()

                #Salvando o formulario em um variavel(objeto)
                newRocklabUser = formUserRocklab.save(commit=False)


                for field in list(RocklabUserForm().base_fields):
                    # setando os atributos preenchidos no formulario para o rocklabuser
                    setattr(user.rocklabuser, field, getattr(newRocklabUser, field))
                    user.rocklabuser.save()

                current_site = get_current_site(request)
                mail_subject = 'Ative sua conta.'

                # Obtendo o conteudo do email sob a forma de pagina html
                email_template = get_template('meulogin/acc_active_email.html')

                #Dados do usuario para mensagem a ser enviada
                message = {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                }

                html_content = email_template.render(message)

                to_email = formCadastro.cleaned_data.get('email')

                # Construindo o email a ser enviado e criando uma nova coneccao com o servidor do email
                email = EmailMultiAlternatives(
                    mail_subject, '', from_email=settings.EMAIL_HOST_USER, to=[to_email]
                )

                # Enviando a pagina renderizada para o email
                email.attach_alternative(html_content, "text/html")

                # Obtendo a conexao com o servidor do email
                email_connection = email.get_connection()

                # Enviando email
                email_connection.username = settings.EMAIL_HOST_USER
                email_connection.password = settings.EMAIL_HOST_PASSWORD
                email.send()


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