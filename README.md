# PowerBallot: A Blockchain-based Voting Platform

<img style="margin: auto; display:flex ; width: 50%;" src="https://media0.giphy.com/media/fveKCnZRN7aOrtWNfj/giphy.gif?cid=ecf05e47lobogvuilxawcc5b24cxk22wbdu7exd9bztitehg&rid=giphy.gif&ct=g" alt="Voting">

PowerBallot is a voting platform that uses blockchain technology to be transparent and safe. It guarantees the confidentiality and integrity of the voting process and makes it simple for voters to cast their ballots from anywhere in the world. PowerBallot makes elections more trustworthy and transparent, making it the perfect answer for authorities, organisations, and companies looking for a safe and dependable voting system.

## To send emails follow these steps

- Log in to your Google Account
- Go to the Google Account Security Page
- Click on the "Security" tab located on the left side of the screen.
- Scroll down to the "Signing in to Google" section and click on the "App passwords" option.
- If "App passwords" section is not visible then turn on 2-factor authentication
- On the App passwords page, select the app (Gmail) and device (custom name) where you want to use the password, and click on "Generate".
- Copy App Password
- Paste the password in your settings.py


​		To send otp make sure `send_otp()` method in `views.py` file looks like this:

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


## How to run

- Install all the (pip) dependency packages.
```
pip install -r requirements.txt
```
- Locate `EMAIL_ADDRESS` and `EMAIL_PASSWORD` variable in `Election/settings.py` file and assign your own valid credentials.
- Locate `manage.py` file and run `python manage.py runserver` in the same directory.
- Locate the URL provided in the terminal and access that. by default it is [http://127.0.0.1:8000](http://127.0.0.1:8000).
