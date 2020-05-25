import pytest
from unittest import mock

from django.contrib.auth import get_user_model
from django.utils.translation import gettext as _
from rest_framework import exceptions

from firebase_admin import auth

from firebase_auth.core.authentication import FirebaseAuthentication


User = get_user_model()


@pytest.fixture
def firebase_authentication():
    return FirebaseAuthentication()


@pytest.fixture
def firebase_uid():
    return 'firebase_uid'


@pytest.fixture
def firebase_payload(firebase_uid):
    return {
        'iss': 'https://securetoken.google.com/firebase-authentication-example', 
        'aud': 'firebase-authentication-example', 
        'auth_time': 1590388218, 
        'user_id': firebase_uid, 
        'sub': firebase_uid, 
        'iat': 1590388218, 
        'exp': 1590391818, 
        'email': 'walisonfilipe@hotmail.com', 
        'email_verified': True, 
        'firebase': {
            'identities': {
                'email': ['walisonfilipe@hotmail.com']
            }, 
            'sign_in_provider': 'password'
        }, 
        'uid': firebase_uid
    }


@pytest.fixture
def user(firebase_uid, db):
    return User.objects.create_user(
        email='walisonfilipe@hotmail.com', 
        password='102030',
        username=firebase_uid
    )


def test_default_uid_field(firebase_authentication):
    assert firebase_authentication.uid_field == User.USERNAME_FIELD


def test_authenticate_with_anonymous_method(firebase_authentication, firebase_uid, firebase_payload):
    firebase_payload['firebase']['sign_in_provider'] = 'anonymous'

    with pytest.raises(exceptions.AuthenticationFailed):
        firebase_authentication.authenticate_credentials(firebase_payload)


def test_authenticate_without_email_verification(
    firebase_authentication, firebase_uid, firebase_payload, settings, user
):
    settings.FIREBASE_EMAIL_VERIFICATION = False

    firebase_payload['email_verified'] = False

    assert firebase_authentication.authenticate_credentials(firebase_payload) == user


def test_authenticate_with_email_verification(
    firebase_authentication, firebase_uid, firebase_payload, settings
):
    settings.FIREBASE_EMAIL_VERIFICATION = True

    firebase_payload['email_verified'] = False

    with pytest.raises(exceptions.AuthenticationFailed):
        firebase_authentication.authenticate_credentials(firebase_payload)


@pytest.mark.django_db
@mock.patch('firebase_auth.core.authentication.auth.get_user')
def test_create_new_user_with_firebase_payload(
    mocked_get_user, firebase_authentication, firebase_payload, firebase_uid
):
    user_data = {
        'localId': firebase_uid,
        'display_name': '',
        'email': 'walisonfilipe@hotmail.com',
        'email_verified': True,
        'disabled': False
    }

    mocked_get_user.return_value = auth.UserRecord(user_data)

    assert not User.objects.exists()

    new_user = firebase_authentication.authenticate_credentials(firebase_payload)

    assert getattr(new_user, User.USERNAME_FIELD) == firebase_uid
    assert new_user.email == user_data['email']


@pytest.mark.parametrize('side_effect,exc_message', [
    [ValueError(), _('Invalid token.')],
    [auth.ExpiredIdTokenError(message='expired id token', cause='expired'), _('Could not log in.')],
    [auth.InvalidIdTokenError(message='invalid id token'), _('Could not log in.')],
    [auth.RevokedIdTokenError(message='revoked id token'), _('Could not log in.')],
])
@mock.patch('firebase_auth.core.authentication.auth.verify_id_token')
def test_authenticate_with_expired_token(
    mocked_verify_id_token, side_effect, exc_message, firebase_authentication, rf
):
    mocked_verify_id_token.side_effect = side_effect

    request = rf.post('/token')

    with pytest.raises(exceptions.AuthenticationFailed) as exc:
        firebase_authentication.authenticate(request)

    assert exc.value.detail == exc_message
