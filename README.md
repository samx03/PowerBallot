# Voting System using Block-Chain

A user can cast his vote by visiting this web platform. For web server scripting we have used python based web framework **`Django`**.



## How to run

1. Install all the (pip) dependency packages (main packages are listed in `requirements.txt`).
2. Locate `EMAIL_ADDRESS` and `EMAIL_PASSWORD` variable in `Election/settings.py` file and assign your valid credentials.


## To send emails follow these steps

- Log in to your Google Account
- Go to the Google Account Security Page
- Click on the "Security" tab located on the left side of the screen.
- Scroll down to the "Signing in to Google" section and click on the "App passwords" option.
- If "App passwords" section is not visible then turn on 2-factor authentication
- On the App passwords page, select the app (Gmail) and device (custom name) where you want to use the password, and click on "Generate".
- Copy App Password
- Paste the password in your settings.py


​		For this make sure `send_otp()` method in `views.py` file looks like this:

```python
...
[success, result] = send_email_otp(email_input)
# [success, result] = [True, '0']
...
```

​		and `get_parties()` method in same file (`views.py`) looks like this:

```python
...
send_email_private_key(request.session['email-id'], private_key)
# print(private_key)
...
```

5. Locate `manage.py` file and run `python manage.py runserver` in the same directory.

6. Locate the URL provided in the terminal and access that. by default it is [http://127.0.0.1:8000](http://127.0.0.1:8000).



  