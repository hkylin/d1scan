from django.shortcuts import render

# Create your views here.
from django.http import HttpResponse

def sqli_model(request):
    return HttpResponse('sqli')

def xss_model(request):
    return HttpResponse('xss')

def vul_model(request):
    return HttpResponse('vul')