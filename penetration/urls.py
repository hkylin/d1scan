from django.conf.urls import url
from django.urls  import path

from penetration import views
urlpatterns = [
    url(r'^sqli_model/$', views.sqli_model, name='sqli_model'),
    url(r'^xss_model/$', views.xss_model, name='xss_model'),
    url(r'^vul_model/$', views.vul_model, name='vul_model'),

]