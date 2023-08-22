import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL, ADMIN_ROLE
from app.validator import UserSchema, GetUserValidation, UserValidation, UserSettingSchema, ChangeUserValidation, \
    GetRoleValidation, RoleSchema
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

api = Blueprint('manage/role', __name__)


@api.route('', methods=['GET'])
@authorization_require()
def get_groups():
    try:
        """ This api get all groups.
            Returns:
            Examples::
        """
        # 1. validate request parameters
        try:
            params = request.args
            params = GetRoleValidation().load(params) if params else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID_PARAMETERS_ERROR', data=err.messages)

        # 2. Process input
        page_number = params.get('page', 1)
        page_size = params.get('page_size', 15)
        search_name = params.get('search_name', None)
        sort = params.get('sort', None)
        order_by = params.get('order_by', 'desc')

        search_name = normalize_search_input(search_name)
        # 3. Query
        query = Role.query
        query = query.filter(Role.key != ADMIN_ROLE)

        if search_name:
            text_like = "%{}%".format(escape_wildcard(search_name.strip()))
            query = query.filter(or_(Role.name.ilike(text_like), Role.key.ilike(text_like)))

        # 4. Sort by column
        if sort:
            column_sorted = getattr(Role, sort)
            query = query.order_by(column_sorted.asc()) if order_by == 'asc' else query.order_by(column_sorted.desc())
        # Default: sort by
        else:
            query = query.order_by(Role.modified_date.desc())

        # 5. Paginator
        paginator = paginate(query, page_number, page_size)
        # 6. Dump data
        roles = RoleSchema(many=True).dump(paginator.items)

        response_data = dict(
            items=roles,
            total_pages=paginator.pages,
            total=paginator.total
        )
        return send_result(data=response_data)
    except Exception as ex:
        return send_error(message=str(ex))