from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response


def login(request):
    return render(request, 'core/login.html')


@api_view(['GET'])
def example(request):
    return Response({'user': request.user.email})

