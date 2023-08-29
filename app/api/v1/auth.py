import json
import uuid
from datetime import timedelta

from app.enums import MESSAGE_ID
from app.validator import AuthValidation, UserSchema, PasswordValidation, VerifyPasswordValidation, RegisterValidation
from flask import Blueprint, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)

from app.api.helper import Token
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, Role, get_roles_key, UserGroupRole, Permission, RolePermission, get_permission_resource
from app.api.helper import send_error, send_result
from app.extensions import jwt, db
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, logged_input
from app.gateway import authorization_require

api = Blueprint('auth', __name__)
ACCESS_EXPIRES = timedelta(days=1)
REFRESH_EXPIRES = timedelta(days=5)


@api.route('/register', methods=['POST'])
def register():
    try:
        try:
            json_req = request.get_json()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442)
        code_lang = request.args.get('code_lang', 'EN')

        # trim input body
        json_body = trim_dict(json_req)
        # validate request body
        is_valid, message_id = data_preprocessing(cls_validator=RegisterValidation, input_json=json_req)
        if not is_valid:
            return send_error(message_id='error')
        email = json_body.get("email")
        password = json_body.get("password")
        full_name = json_body.get("full_name")
        phone = json_body.get("phone")
        address = json_body.get("address")
        check_exits_user = User.query.filter_by(email=email).first()
        if check_exits_user:
            return send_error(message='EXISTED_EMAIL')
        role = Role.query.filter(Role.key == 'permissionuserbasic').first()
        # register user
        new_user = User(
            id=str(uuid.uuid4()),
            created_date=get_timestamp_now(),
            modified_date=get_timestamp_now(),
            password_hash=generate_password_hash(password),
            email=email,
            address=address,
            phone=phone,
            full_name=full_name
        )
        db.session.add(new_user)
        db.session.flush()
        user_role = UserGroupRole(id=str(uuid.uuid4()), user_id=new_user.id, role_id=role.id)
        db.session.add(user_role)
        db.session.flush()
        db.session.commit()
        data = UserSchema().dump(new_user)
        return send_result(data=data, message='Success', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


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
        try:
            json_req = request.get_json()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442)
        code_lang = request.args.get('code_lang', 'EN')

        # trim input body
        json_body = trim_dict(json_req)

        # validate request body
        is_valid, message_id = data_preprocessing(cls_validator=AuthValidation, input_json=json_req)
        if not is_valid:
            return send_error(message='Error', message_id=MESSAGE_ID, code_lang=code_lang)

        # Check username and password
        email = json_body.get("email")
        password = json_body.get("password")
        is_admin = json_body.get("is_admin")

        user = User.query.filter(User.email == email).first()
        if user is None or (password and not check_password_hash(user.password_hash, password)):
            return send_error(message='Fail', message_id=MESSAGE_ID, code_lang=code_lang)
        roles = get_roles_key(user.id)
        # Check permission login (from user/admin side?)
        is_authorized = False
        if is_admin:
            if 'permissionadminbasic' in roles:
                is_authorized = True
        else:
            if 'permissionuserbasic' in roles:
                is_authorized = True
        if not is_authorized:
            return send_error(message='YOU_DO_NOT_HAVE_PERMISSION', message_id=MESSAGE_ID, code_lang=code_lang)

        if not user.status:
            return send_error(message='INACTIVE_ACCOUNT_ERROR', message_id=MESSAGE_ID, code_lang=code_lang)

        access_token = create_access_token(identity=user.id, expires_delta=ACCESS_EXPIRES,
                                           user_claims={"force_change_password": user.force_change_password})
        refresh_token = create_refresh_token(identity=user.id, expires_delta=REFRESH_EXPIRES,
                                             user_claims={"force_change_password": user.force_change_password})
        list_permission = get_permission_resource(user.id)
        # Store the tokens in our store with a status of not currently revoked.
        Token.add_token_to_database(access_token, user.id)
        Token.add_token_to_database(refresh_token, user.id)
        Token.add_list_permission(user.id, list_permission)

        data: dict = UserSchema().dump(user)
        data.setdefault('access_token', access_token)
        data.setdefault('refresh_token', refresh_token)

        return send_result(data=data, message_id='MESSAGE_ID_5', code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


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
    code_lang = request.args.get('code_lang', 'EN')
    user_identity = get_jwt_identity()
    user = User.query.filter_by(id=user_identity).first()

    access_token = create_access_token(identity=user.id, expires_delta=ACCESS_EXPIRES,
                                       user_claims={"force_change_password": user.force_change_password})

    # Store the tokens in our store with a status of not currently revoked.
    Token.add_token_to_database(access_token, user_identity)

    data = {
        'access_token': access_token
    }

    return send_result(data=data, message_id=MESSAGE_ID, code_lang=code_lang)


@api.route('/logout', methods=['DELETE'])
@jwt_required
def logout():
    """
    This api logout current user, revoke current access token

    Examples::

    """
    try:
        code_lang = request.args.get('code_lang', 'EN')
        jti = get_raw_jwt()['jti']
        Token.revoke_token(jti)  # revoke current token from database

        return send_result(message="Logout successfully!", message_id=MESSAGE_ID,code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(str(ex))


@api.route('/change-password', methods=['PUT'])
@jwt_required
def change_password():
    """
    This is controller of the login api

    Requests Body:
            password: string, require
    EX:
        {
            "password": "admin@1234"
        }
    """
    try:
        code_lang = request.args.get('code_lang', 'EN')

        try:
            json_req = request.get_json()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442,
                              code_lang=code_lang, message_id=MESSAGE_ID)
        user_id = get_jwt_identity()
        # trim input body
        json_body = trim_dict(json_req)
        # validate request body
        validator_input = PasswordValidation()
        is_not_validate = validator_input.validate(json_body)
        if is_not_validate:
            return send_error(data=is_not_validate, message='INVALID_PASSWORD')
        user = User.query.filter(User.id == user_id)
        if user is None:
            return send_error(message='NOT_FOUND_ERROR')
        current_password = json_req.get("current_password")
        password = json_body.get("password")
        if not check_password_hash(user.password_hash, current_password):
            return send_error(message='INCORRECT_PASSWORD')
        if password == current_password:
            return send_error(message='SAME_AS_CURRENT_PASSWORD')
        is_admin = False if User.type == 1 else True
        user.reset_password = 1  # Flag reset password
        user.password_hash = generate_password_hash(password)
        user.modified_date_password = get_timestamp_now()
        user.modified_date = get_timestamp_now()
        user.force_change_password = False
        db.session.commit()
        message = 'CHANGE_DEFAULT_PASS_SUCCESS' if is_admin else 'CHANGE_DEFAULT_PASS_SUCCESS_USER_SITE'
        # revoke all token of current user  from database
        Token.revoke_all_token(user_id)
        return send_result(data=UserSchema().dump(user), message=message, message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(str(ex))


@api.route('/verify', methods=['POST'])
@authorization_require()
def verify_password():
    """ This api for all user change their password.

        Request Body:

        Returns:

        Examples::

    """
    code_lang = request.args.get('code_lang', 'EN')

    user = User.query.filter(User.id == get_jwt_identity()).first()
    try:
        json_req = request.get_json()
    except Exception as ex:
        return send_error(message="Request Body incorrect json format: " + str(ex), code=442)

    # logged input fields
    logged_input(json.dumps(json_req))

    # validate request body
    validator_input = VerifyPasswordValidation()
    is_not_validate = validator_input.validate(json_req)
    if is_not_validate:
        return send_error(data=is_not_validate, message='INVALID_PASSWORD', code_lang=code_lang, message_id=MESSAGE_ID)

    current_password = json_req.get("current_password")

    if not check_password_hash(user.password_hash, current_password):
        return send_error(message='INCORRECT_PASSWORD', message_id=MESSAGE_ID, code_lang=code_lang)

    return send_result(data={}, message_id='MESSAGE_ID_4', code_lang=code_lang)


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


# @api.route('/set-role-permission', methods=['GET'])
# def set_role_permission():
#     try:
#         role = Role.query.filter(Role.key == 'permissionuserbasic').first()
#         permissions = Permission.query.filter(Permission.key == 'permissionuserbasic').all()
#         list_add = []
#         for permission in permissions:
#             role_permission = RolePermission(id=str(uuid.uuid1()), permission_id=permission.id, role_id=role.id)
#             list_add.append(role_permission)
#         db.session.bulk_save_objects(list_add)
#         db.session.commit()
#         return send_result(message='oke')
#     except Exception as ex:
#         db.session.rollback()
#         return send_error(str(ex))

