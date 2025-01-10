from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required

# Home View
@login_required(login_url='login')  # Redirects to login if user is not authenticated
def home(request):
    print("Authenticated:", request.user.is_authenticated)
    return render(request, 'Home.html')

# Login View
def login(request):
    if request.method == 'POST':
        userid = request.POST.get('userid')
        pass1 = request.POST.get('password')

        if not userid or not pass1:
            message = 'Username and password are required'
            return render(request, 'Login.html', {'message': message})

        user = authenticate(request, username=userid, password=pass1)
        if user is not None:
            auth_login(request, user)  # Logs in the user
            return redirect('home')
        else:
            message = 'Invalid username or password'
            return render(request, 'Login.html', {'message': message})
    return render(request, 'Login.html')

# Register View
def register(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        confpasswd = request.POST.get('confirm-password')

        if not username or not password or not confpasswd:
            message = 'All fields are required'
            return render(request, 'Signup.html', {'message': message})

        if password != confpasswd:
            message = 'Passwords do not match'
            return render(request, 'Signup.html', {'message': message})

        try:
            # Use create_user to create a new user
            my_user = User.objects.create_user(username=username, password=password)
            my_user.save()
            return redirect('login')
        except Exception as e:
            message = f'Error occurred: {e}'
            return render(request, 'Signup.html', {'message': message})

    return render(request, 'Signup.html')  # Corrected template name
