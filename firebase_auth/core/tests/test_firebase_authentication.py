import pytest

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


@pytest.fixture
def make_request(rf):
    def _make_request(token):
        headers = {
            'HTTP_AUTHORIZATION': token
        }
        return rf.post('/token', **headers)

    return _make_request


@pytest.fixture
def fake_request(make_request):
    return make_request('Bearer token')


def test_default_uid_field(firebase_authentication):
    assert firebase_authentication.uid_field == User.USERNAME_FIELD


@pytest.mark.parametrize('token,extracted', [
    ('Bearer token', b'token'),
    ('InvalidPrefix token', None)
])
def test_get_token(firebase_authentication, make_request, token, extracted):
    request = make_request(token)

    token = firebase_authentication.get_token(request)

    assert token == extracted


@pytest.mark.parametrize('token,exc_message', [
    ('Bearer', _('Invalid Authorization header. No credentials provided.')),
    (
        'Bearer token with spaces', 
        _('Invalid Authorization header. Token string should not contain spaces.')
    ),
])
def test_get_token_raises_exception(firebase_authentication, make_request, token, exc_message):
    request = make_request(token)

    with pytest.raises(exceptions.AuthenticationFailed) as exc:
        firebase_authentication.get_token(request)
    
    assert exc.value.detail == exc_message


def test_valid_authentication(
    firebase_authentication, firebase_payload, fake_request, user, mocker
):
    mocker.patch(
        'firebase_auth.core.authentication.auth.verify_id_token',
        return_value=firebase_payload
    )

    authenticated_user, payload = firebase_authentication.authenticate(fake_request)
    
    assert authenticated_user == user
    assert payload == firebase_payload


def test_authenticate_with_invalid_token(
    firebase_authentication, fake_request, user, mocker
):
    mocker.patch(
        'firebase_auth.core.authentication.FirebaseAuthentication.get_token',
        return_value=None
    )

    result = firebase_authentication.authenticate(fake_request)

    assert result is None


def test_authenticate_with_anonymous_method(firebase_authentication, firebase_uid, firebase_payload):
    firebase_payload['firebase']['sign_in_provider'] = 'anonymous'

    with pytest.raises(exceptions.AuthenticationFailed):
        firebase_authentication.authenticate_credentials(firebase_payload)


def test_authenticate_with_email_verification_disabled(
    firebase_authentication, firebase_uid, firebase_payload, settings, user
):
    settings.FIREBASE_EMAIL_VERIFICATION = False

    firebase_payload['email_verified'] = False

    assert firebase_authentication.authenticate_credentials(firebase_payload) == user


def test_authenticate_with_email_verification_enabled(
    firebase_authentication, firebase_uid, firebase_payload, settings
):
    settings.FIREBASE_EMAIL_VERIFICATION = True

    firebase_payload['email_verified'] = False

    with pytest.raises(exceptions.AuthenticationFailed):
        firebase_authentication.authenticate_credentials(firebase_payload)


@pytest.mark.django_db
def test_create_new_user_with_firebase_payload(
    firebase_authentication, firebase_payload, firebase_uid, mocker
):
    user_data = {
        'localId': firebase_uid,
        'display_name': '',
        'email': 'walisonfilipe@hotmail.com',
        'email_verified': True,
        'disabled': False
    }

    mocker.patch(
        'firebase_auth.core.authentication.auth.get_user',
        return_value=auth.UserRecord(user_data)
    )

    assert not User.objects.exists()

    new_user = firebase_authentication.authenticate_credentials(firebase_payload)

    assert getattr(new_user, User.USERNAME_FIELD) == firebase_uid
    assert new_user.email == user_data['email']


@pytest.mark.parametrize('side_effect,exc_message', [
    [ValueError(), _('Invalid firebase ID token.')],
    [auth.ExpiredIdTokenError(message='expired id token', cause='expired'), _('Could not log in.')],
    [auth.InvalidIdTokenError(message='invalid id token'), _('Could not log in.')],
    [auth.RevokedIdTokenError(message='revoked id token'), _('Could not log in.')],
])
def test_authenticate_with_expired_token(
    mocker, side_effect, exc_message, firebase_authentication, fake_request
):
    mocker.patch(
        'firebase_auth.core.authentication.auth.verify_id_token',
        side_effect=side_effect
    )

    with pytest.raises(exceptions.AuthenticationFailed) as exc:
        firebase_authentication.authenticate(fake_request)

    assert exc.value.detail == exc_message


@pytest.mark.parametrize('auth_prefix,realm,result_header', [
    ('Bearer', 'api', 'Bearer realm="api"'),
    ('Token', 'api', 'Token realm="api"'),
])
def test_authenticate_header(
    firebase_authentication, fake_request, auth_prefix, realm, result_header
):
    firebase_authentication.auth_header_prefix = auth_prefix

    header = firebase_authentication.authenticate_header(fake_request)

    assert header == result_header