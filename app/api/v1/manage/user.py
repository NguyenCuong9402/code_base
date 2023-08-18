import json
from datetime import timedelta
from app.validator import AuthValidation, UserSchema, PasswordValidation, VerifyPasswordValidation
from flask import Blueprint, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)

from app.api.helper import Token
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, RedisModel
from app.api.helper import send_error, send_result
from app.extensions import jwt, db
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL, logged_input
from app.gateway import authorization_require

api = Blueprint('user', __name__)