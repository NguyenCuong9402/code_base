import json
from datetime import timedelta
from app.validator import AuthValidation, UserSchema
from flask import Blueprint, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)

from app.api.helper import Token
from werkzeug.security import check_password_hash
from app.models import User
from app.api.helper import send_error, send_result
from app.extensions import jwt, db
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL

api = Blueprint('auth', __name__)
ACCESS_EXPIRES = timedelta(days=1)
REFRESH_EXPIRES = timedelta(days=5)


@api.route('/login', methods=['POST'])
def login():
    """
    This is controller of the login api

    Requests Body:
            email: string, require
            password: string, require
            is_admin: Boolean, require

    EX:
        {
            "email": "admin@boot.ai",
            "password": "admin",
            "is_admin": False
        }
    """

    try:
        json_req = request.get_json()
    except Exception as ex:
        return send_error(message="Request Body incorrect json format: " + str(ex), code=442)

    # trim input body
    json_body = trim_dict(json_req)

    # validate request body
    is_valid, message_id = data_preprocessing(cls_validator=AuthValidation, input_json=json_req)
    if not is_valid:
        return send_error(message_id=message_id)

    # Check username and password
    email = json_body.get("email")
    password = json_body.get("password")
    is_admin = json_body.get("is_admin")

    user = User.query.filter(User.email == email).first()
    if user is None or (password and not check_password_hash(user.password_hash, password)):
        return send_error(message='Fail')

    # Check permission login (from user/admin side?)
    is_authorized = False
    if is_admin:
        if 'Permission_Admin_Basic' in User.roles_key:
            is_authorized = True
    else:
        if 'Permission_User_Basic' in User.roles_key:
            is_authorized = True
    if not is_authorized:
        return send_error(message='YOU_DO_NOT_HAVE_PERMISSION')

    if not user.status:
        return send_error(message='INACTIVE_ACCOUNT_ERROR')

    access_token = create_access_token(identity=user.id, expires_delta=ACCESS_EXPIRES)
    refresh_token = create_refresh_token(identity=user.id, expires_delta=REFRESH_EXPIRES)

    # Store the tokens in our store with a status of not currently revoked.
    Token.add_token_to_database(access_token, user.id)
    Token.add_token_to_database(refresh_token, user.id)

    data: dict = UserSchema().dump(user)
    data.setdefault('access_token', access_token)
    data.setdefault('refresh_token', refresh_token)

    return send_result(data=data)


@api.route('/refresh', methods=['POST'])
@jwt_refresh_token_required
def refresh():
    """
    This api use for refresh expire time of the access token. Please inject the refresh token in Authorization header

    Requests Body:

        refresh_token: string,require
        The refresh token return to the login API

    Returns:

        access_token: string
        A new access_token

    Examples::

    """

    user_identity = get_jwt_identity()
    user = User.get_by_id(user_identity)

    access_token = create_access_token(identity=user.id, expires_delta=ACCESS_EXPIRES,
                                       user_claims={"force_change_password": user.force_change_password})

    # Store the tokens in our store with a status of not currently revoked.
    Token.add_token_to_database(access_token, user_identity)

    data = {
        'access_token': access_token
    }

    return send_result(data=data)


@api.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    """
    This api logout current user, revoke current access token

    Examples::

    """

    jti = get_raw_jwt()['jti']
    Token.revoke_token(jti)  # revoke current token from database

    return send_result(message="Logout successfully!")


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    """
    :param decrypted_token:
    :return:
    """
    return Token.is_token_revoked(decrypted_token)


@jwt.expired_token_loader
def expired_token_callback():
    """
    The following callbacks are used for customizing jwt response/error messages.
    The original ones may not be in a very pretty format (opinionated)
    :return:
    """
    return send_error(code=401, message='SESSION_TOKEN_EXPIRED')


@jwt.revoked_token_loader
def revoked_token_callback():
    return send_error(code=401, message='SESSION_TOKEN_EXPIRED')
