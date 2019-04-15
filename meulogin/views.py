# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render, redirect

from django.contrib.auth.forms import UserCreationForm

from django.contrib.auth import login, authenticate

# Create your views here.

#
# def chamahtml(request):
#     usuario = request.user
#     context = {
#         'nome_usuario': usuario ,
#         'email': 'marcos@gmail.com',
#         'endereco': 'Rua das Palmeiras',
#         'cores_favoritas': ['azul','amarelo'],
#     }
#     return render(request, 'meulogin/index.html', context)

def cadastrar_usuario(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('sucesso')
    else:
        form = UserCreationForm()
    return render(request, "meulogin/index.html", {'form':form})

def sucesso_cadastrar_usuario(request):
    # print request

    return render(request, "meulogin/sucesso.html")