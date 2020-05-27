from django.conf import settings
from rest_framework.settings import APISettings


FIREBASE_AUTH_SETTINGS = "FIREBASE_AUTH"

USER_SETTINGS = getattr(settings, FIREBASE_AUTH_SETTINGS)

DEFAULTS = {"SERVICE_ACCOUNT_KEY_FILE": "", "EMAIL_VERIFICATION": False}

IMPORT_STRINGS = ()

firebase_auth_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)
