from django.apps import AppConfig

from firebase_admin import credentials, initialize_app
from firebase_auth.settings import firebase_auth_settings


class FirebaseAuthConfig(AppConfig):
    name = "firebase_auth"

    def ready(self) -> None:
        initialize_app(
            credentials.Certificate(firebase_auth_settings.SERVICE_ACCOUNT_KEY_FILE)
        )
