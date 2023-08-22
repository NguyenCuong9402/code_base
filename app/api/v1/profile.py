import json
import uuid
from datetime import timedelta
from app.validator import AuthValidation, UserSchema, PasswordValidation, VerifyPasswordValidation, RegisterValidation, \
    UserParentSchema, UpdateProfileSchema
from flask import Blueprint, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)

from app.api.helper import Token
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, TokenModel, Role, RolePermission, Permission, get_roles_key, Group, UserGroupRole
from app.api.helper import send_error, send_result
from app.extensions import jwt, db
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL, logged_input
from app.gateway import authorization_require

api = Blueprint('profile', __name__)


@api.route('', methods=['GET'])
@authorization_require()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()
        return send_result(data=UserSchema(only=['email', 'phone', 'full_name', 'address',
                                                 'birthday', 'avatar_url', 'created_date']).dump(user))
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('', methods=['PUT'])
@authorization_require()
def change_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()
        try:
            json_req = request.get_json()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442)
        # trim input body
        json_body = trim_dict(json_req)
        # validate request body
        validator_input = UpdateProfileSchema()
        is_not_validate = validator_input.validate(json_body)
        if is_not_validate:
            return send_error(data=is_not_validate, message='INVALID_PASSWORD')
        if user is None:
            return send_error(message='NOT_FOUND_ERROR')
        for key in json_req.keys():
            user.__setattr__(key, json_req[key])
        db.session.flush()
        db.session.commit()

    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))