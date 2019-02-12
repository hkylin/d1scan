from django.shortcuts import render

# Create your views here.
def index(request):
    data = {
        'page_name': '仪表盘'
    }
    return render(request, 'index.html', data)