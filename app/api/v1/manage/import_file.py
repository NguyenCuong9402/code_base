
import pandas as pd
import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL
from app.validator import UserSchema, GetUserValidation, UserValidation, UserSettingSchema, ChangeUserValidation
from flask import Blueprint, request
from flask_jwt_extended import (get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)
from sqlalchemy import or_, func, distinct
from app.models import User, Group, UserGroupRole, Role, Permission, UserSetting
from app.api.helper import send_error, send_result, Token
from app.extensions import jwt, db, logger
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL, \
    normalize_search_input, escape_wildcard, generate_password
from app.gateway import authorization_require
from marshmallow import ValidationError
import uuid

api = Blueprint('manage/import_file', __name__)


@api.route('/upload', methods=['POST'])
@authorization_require()
def upload_file():
    try:
        file = request.files['file']
        if file:
            # Đọc dữ liệu từ tệp Excel bằng pandas
            df = pd.read_excel(file)
            list_add_permission = []
            # Lặp qua từng hàng của DataFrame và thêm vào cơ sở dữ liệu
            for index, row in df.iterrows():
                existing_permission = Permission.query.filter(or_(Permission.key == row['key'],
                                                                  Permission.name == row['name']),
                                                              Permission.resource == row['resource'])
                if existing_permission is None:
                    permission = Permission(
                        id=str(uuid.uuid4()),
                        key=row['key'],
                        name=row['name'],
                        resource=row['resource']
                    )
                    list_add_permission.append(permission)
            db.session.bulk_save_objects(list_add_permission)
            db.session.commit()
            return send_result(message="File uploaded and data imported successfully.")
        else:
            return send_error(message="No file uploaded.")
    except Exception as e:
        return send_error(message=str(e))