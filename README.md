# Django Rest Firebase Auth
Use firebase authentication with your django rest framework project

[![codecov](https://codecov.io/gh/walison17/django-rest-firebase-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/walison17/django-rest-firebase-auth)

## Requirements
- Python (3.5, 3.6, 3.7 or 3.8)
- Django >= 2.2
- Django Rest Framework


## Installation

```
pip install django-rest-firebase-auth
```

On your project's `settings.py` add this to the `REST_FRAMEWORK` configuration

```
REST_FRAMEWORK = {
  ...
  'DEFAULT_AUTHENTICATION_CLASSES': [
    'firebase_auth.authentication.FirebaseAuthentication'
  ]
  ...
}
```

Get admin credentials `.json` from the Firebase SDK and add them to your project

Also in your project's `settings.py`:

```
FIREBASE_APP_CREDENTIALS = 'path_to_your_credentials.json'
```

if you want to allow only users with verified emails

```
FIREBASE_EMAIL_VERIFICATION = True
```
