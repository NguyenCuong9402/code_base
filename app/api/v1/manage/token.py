import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL
from app.validator import UserSchema, GetUserValidation, UserValidation, UserSettingSchema, ChangeUserValidation
from flask import Blueprint, request
from flask_jwt_extended import (get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)
from sqlalchemy import or_, func, distinct
from app.models import User, Group, UserGroupRole, Role, Permission, UserSetting, TokenModel
from app.api.helper import send_error, send_result, Token
from app.extensions import jwt, db, logger
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL, \
    normalize_search_input, escape_wildcard, generate_password
from app.gateway import authorization_require
from marshmallow import ValidationError
import uuid

api = Blueprint('token', __name__)


@api.route('/auto-remove-token', methods=['DELETE'])
@authorization_require()
def remove_token():
    try:
        TokenModel.query.filter(TokenModel.expires < get_timestamp_now()).delete()
        db.session.flush()
        db.session.commit()
        return send_result(message='Done')
    except Exception as ex:
        db.session.flush()
        return send_error(message=str(ex))