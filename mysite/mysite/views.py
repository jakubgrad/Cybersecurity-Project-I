from django.http import HttpResponse
from django.template import loader
from django.shortcuts import render, redirect
from django.middleware.csrf import rotate_token
import sqlite3
import hashlib
import pickle
import logging

logger = logging.getLogger("myapp")

def hash_password(password):
    # FLAW 4
    # A02:2021-Cryptographic Failures
    # SHA-1 is an insecure algorithm because it's fast to compute,
    # which means an attacker can try to generate many hashes for
    # common passwords in order to find a match once they compromise
    # the database or use a list from the internet of known hashes. 
    # E.g. I found the password "admin" from a hash of it online.
    return hashlib.sha1(password.encode()).hexdigest()
    
    # FIX 4
    # Have a strong policy for passwords when registering users.
    # E.g., don't allow passwords from public repositories of 
    # popular passwords. Also, use a stronger encryption algorithm,
    # e.g. sha256 as suggested in this fix:
    #return hashlib.sha256(data).hexdigest()

def homePageView(request):
    return render(request, 'pages/home.html')

def blogPageView(request):
    if request.method == 'POST':        
        #FLAW 2
        # A01:2021-Broken Access Control
        #It's possible to rewrite someone else's blog by putting their name in the hidden input in the POST form.
        username = request.POST.get('username', '')
        #FIX 2
        #Comment last line of code and uncomment the one below:
        #username = request.session['username']

        # FLAW 3
        # A07:2021-Identification and Authentication Failures
        # Even if we fix the above flaw, this form is still vulnerable to a so-called replay
        # attack because of how the logout function on the bottom of this file was implemented.
        # Currently, the logout button just sets the logged_in value in request.session to False,
        # but doesn't reset the csrf token or cookie. So if you used this application on a
        # public computer (haha, who still uses those) then even though you logged out, someone
        # can copy the csrf token, session and sessionid values, and use a tool such as postman
        # to edit your blog. It sounds unlikely but I've personally used tools that didn't always
        # work when you clicked log out (I've noticed it was even happening to Facebook a few 
        # years ago). For FIX 3 scroll to the bottom of this file to the logout function!

        blog = request.POST.get('blog', '')
        con = sqlite3.connect("bloggify.sqlite")
        cur = con.cursor()
        query = "UPDATE users SET blog=? WHERE username=?"
        res = cur.execute(query, (blog,username))
        result = res.fetchone()
        con.commit()
        con.close()

    if request.session.get('logged_in'):
        con = sqlite3.connect("bloggify.sqlite")
        cur = con.cursor()
        query = "SELECT username, blog FROM users WHERE username=?"
        username = request.session['username']
        res = cur.execute(query, (username,))
        result = res.fetchone()
        con.close()
        if result:
            username, blog = result
            return render(request, 'pages/blog.html', {'username' : username, 'blog' : blog})
            return HttpResponse(f"Hi {username}, your blog is '{blog}'")
        else:
            return HttpResponse(f"It seems that there's no blog associated with your credentials!")
    else:
        return redirect('/home/')
    

def homePageViewTemplateWithData(request):
    return render(request, 'pages/index.html', {'msg' : 'Hi!', 'from' : 'Ada'})

def loginPageView(request):
    if request.session.get('logged_in'):
        return redirect('/blog/')
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        hashed_password = hash_password(password=password)
        con = sqlite3.connect("bloggify.sqlite")
        cur = con.cursor()

        #FLAW 1
        #SQL INJECTION
        #It's possible to log in e.g. as first user with username equal to ' OR '1'='1' --
        #Or as anyone with a known username or even delete all records
        query = f"SELECT username, blog FROM Users WHERE username='{username}' AND password='{hashed_password}'"
        res = cur.execute(query)

        #FLAW 1 Fix:
        #Comment last two lines and uncomment these:
        #query = "SELECT username, blog FROM Users WHERE username=? AND password=?"
        #res = cur.execute(query, (username, password))

        result = res.fetchone()
        con.close()
        if result:
            username, blog = result
            request.session['username'] = username
            request.session['logged_in'] = True
            return redirect('/blog/')
        #FLAW 5
        #A09:2021 – Security Logging and Monitoring Failures
        #The application does not generate log messages for any user activity.
        #Here, if the username/password pair doesn't correspond to a record,
        #the user is simply redirected to the login page.
        #Failed login attempts are not logged to a file or to the console,
        #hence the application isn't monitored for suspicious activity at all.
        #A password could be bruteforced and administrators would never notice.

        #FLAW 5 Fix:
        #Log failed log-in attempts (other types of suspicious activity could also
        #be logged, e.g. mass deletion of database records or unauthorized access)
        #into a file so that the record of failed login attempts persists even if the
        #process terminates. From the log it's possible to see what IP address carried
        #out the failed logins and which user was the target. See the logging configuration
        #at the bottom of settings.py for more details!
        #Uncomment the following lines:
        
        # x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        # if x_forwarded_for:
        #     ip = x_forwarded_for.split(',')[0]
        # else:
        #     ip = request.META.get('REMOTE_ADDR')
        # logger.warning(f"Login attempt from IP {ip} for username  {username} failed")

        return render(request, 'pages/login.html')
    return render(request, 'pages/login.html')

def registerPageView(request):
    if request.session.get('logged_in'):
        return redirect('/blog/')
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        

        hashed_password = hash_password(password)
        #We should also check if someone with that username already exists... is that another flaw?
        con = sqlite3.connect("bloggify.sqlite")
        cur = con.cursor()
        query = "INSERT INTO users (username,password,blog) VALUES (?,?,?)"
        res = cur.execute(query, (username,hashed_password,""))
        result = res.fetchone()
        request.session["username"] = username
        request.session["logged_in"] = True
        con.commit()
        con.close()
        return redirect('/login/')
    return render(request, 'pages/register.html')
    

def logout(request):
    request.session['logged_in'] = False
    response = render(request, 'pages/login.html')
    
    # FIX 3
    # Uncomment the three lines of code below!
    # This will remove the session data and csrftoken and prevent a replay attack
    #request.session.flush() 
    #rotate_token(request)
    #response = render(request, 'pages/login.html')
    
    return response