from django.http import HttpResponse
from django.template import loader
from django.shortcuts import render

def addView(request):
    first = request.GET.get('first')
    second = request.GET.get('second')
    return HttpResponse(str(int(first)+int(second)))

def multiplyView(request):
    return HttpResponse("2")
    first = request.GET.get('first')
    second = request.GET.get('second')
    print(first)
    return HttpResponse(str(int(first)*int(second)))

def homePageView(request):
    #template = loader.get_template('pages/index.html')
    #return HttpResponse(template.render())
    return render(request, 'pages/index.html', {'username' : 'Kuba'})

def homePageViewTemplateWithData(request):
    return render(request, 'pages/index.html', {'msg' : 'Hi!', 'from' : 'Ada'})

def loginPageView(request):
    return render(request, 'pages/login.html')
    #return HttpResponse('Hello Web!')

def logout(request):
    #request.session.flush()  # This will remove the session data
    request.session['items'] = 2
    #user_logged_in = request.sessions['user_logged_in']
    #print(f"user_logged_in: {user_logged_in}")
    #request.sessions['user_logged_in'] = False
    return render(request, 'pages/login.html')
