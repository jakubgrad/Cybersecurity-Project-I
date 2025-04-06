from django.http import HttpResponse
from django.template import loader
from django.shortcuts import render, redirect
import sqlite3
import hashlib
import pickle

def hash_password(password):
    
    # FLAW 4
    # Cryptographic Failure
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

def blogPageView(request):
    if request.method == 'POST':
        
        #FLAW 2
        #It's possible to rewrite someone else's blog by putting their name in the hidden input in the POST form.
        username = request.POST.get('username', '')
        #FIX 2
        #Comment last line of code and uncomment the one below:
        #username = request.session['username']

        # FLAW 5
        # Even if we fix the above flaw, this form is still vulnerable to a so-called replay
        # attack because of how the logout function on the bottom of this file was implemented.
        # Currently, the logout button just sets the logged_in value in request.session to False,
        # but doesn't reset the csrf token or cookie. So if you used this application on a
        # public computer (haha, who still uses those) then even though you logged out, someone
        # can copy the csrf token, session and sessionid values, and use a tool such as postman
        # to edit your blog. It sounds unlikely but I've personally used tools that didn't always
        # work when you clicked log out (I've noticed it was even happening to Facebook a few 
        # years ago). For FIX 5 scroll to the bottom of this file to the logout function!

        blog = request.POST.get('blog', '')
        print(f"Someone with a username '{username}' rewrote their blog with the following data:")
        print(blog)
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
        return HttpResponse("You are not logged in. Go to /login")
    

def homePageViewTemplateWithData(request):
    return render(request, 'pages/index.html', {'msg' : 'Hi!', 'from' : 'Ada'})

def loginPageView(request):
    if request.session.get('logged_in'):
        return redirect('/blog/')
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        hashed_password = hash_password(password=password)
        print(username)
        print(password)
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
        print(f"result is {result}")
        con.close()
        if result:
            username, blog = result
            request.session['username'] = username
            request.session['logged_in'] = True
            return redirect('/blog/')
        return render(request, 'pages/login.html')
    return render(request, 'pages/login.html')
        #return HttpResponse('Hello Web!')

def registerPageView(request):
    if request.session.get('logged_in'):
        return redirect('/blog/')
    if request.method == 'POST':
        username = request.POST.get('username', '')
        password = request.POST.get('password', '')
        #FLAW 3
        #A09:2021 – Security Logging and Monitoring Failures
        #The application is not monitored for brute force.
        #Failed loggings and registering attempts are not logged.
        #If the form doesn't check if a username is already taken,
        # an adversary can use the register form to create a 
        # username-password pair that they can log in with and 
        # retrieve another users blog. Or, a password of another user
        # can be bruteforced using the login form, since there is no 
        # password policy!

        #FIX 3
        #Uncomment the below lines:
        #err = "Something is wrong with your password"
        #def check_password_strength(password):
            #err = None
            #if len(password) < 8:
                #err = "Password is too short"
            #if not any(char.isdigit() for char in password):
                #err = "Password should have at least one number"
            #if not any(char.isupper() for char in password):
                #err="Password should have at least one uppercase letter"
            #if not any(char.islower() for char in password):
                #err="Password should have at least one lowercase letter"
            #if not any(char in '!@#$%^&*()_+' for char in password):
                #err="Password should have at least one special character"
            #return err
        #err = check_password_strength(password=password)
        #if err:
            #return render(request, 'pages/register.html', {'err':err})


        print(f"Someone registers with username '{username}' and password {password}.")
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
    what_was_there = request.session['items']
    print(f"what_was_there: {what_was_there}")
    
    request.session['logged_in'] = False
    # FIX 5
    # Uncomment the below line of code!
    # This will remove the session data and prevent a replay attack
    # request.session.flush()  
    return render(request, 'pages/login.html')
