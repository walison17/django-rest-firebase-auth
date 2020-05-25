from django.urls import path

from . import views

app_name = 'core'

urlpatterns = [
    path('login/', views.login, name='login'),
    path('api/', views.example, name='api.example')
]