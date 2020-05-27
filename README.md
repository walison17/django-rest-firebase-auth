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
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "firebase_auth.authentication.FirebaseAuthentication"
    ]
    ...
}
```

Get your admin credentials `.json` from the Firebase SDK and add them to your project

```
FIREBASE_AUTH = {
    "SERVICE_ACCOUNT_KEY_FILE" = "path_to_your_credentials.json"
}
```

The `django-rest-firebase-auth` comes with the following settings as default, which can be overridden in your project's `settings.py`.

```
FIREBASE_AUTH = {
    "SERVICE_ACCOUNT_KEY_FILE": "",

    # require that user has verified their email
    "EMAIL_VERIFICATION": False
}
```
