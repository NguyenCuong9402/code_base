import json
from datetime import timedelta

from sqlalchemy_pagination import paginate

from app.enums import ADMIN_EMAIL
from app.validator import AuthValidation, UserSchema, PasswordValidation, VerifyPasswordValidation, GetUserValidation
from flask import Blueprint, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)
from sqlalchemy import or_, func, distinct
from app.api.helper import Token
from werkzeug.security import check_password_hash, generate_password_hash
from app.models import User, RedisModel
from app.api.helper import send_error, send_result
from app.extensions import jwt, db, logger
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL, logged_input, \
    normalize_search_input, escape_wildcard
from app.gateway import authorization_require
from marshmallow import ValidationError

api = Blueprint('user', __name__)


@api.route('', methods=['GET'])
@authorization_require()
def get_users():
    try:
        """ This api get all user.
            Returns:
            Examples::
        """
        # 1. validate request parameters
        try:
            params = request.args
            params = GetUserValidation().load(params) if params else dict()
            user_create_id = get_jwt_identity()
            user = User.get_by_id(user_create_id)
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
        status = params.get('status', None)

        search_name = normalize_search_input(search_name)
        # 3. Query
        query = User.query
        # Remove acc admin.fit.mta@gmail.com
        query = query.filter(User.email != ADMIN_EMAIL, User.is_anonymous != 1)
        if status is not None:
            query = query.filter(User.status == status)

        if search_name:
            text_like = "%{}%".format(escape_wildcard(search_name.strip()))
            query = query.filter(or_(User.full_name.collate('utf8mb4_bin').ilike(text_like),
                                     User.email.collate('utf8mb4_bin').ilike(text_like)))
        # 4. Sort by column
        if sort:
            column_sorted = getattr(User, sort)
            query = query.order_by(column_sorted.asc()) if order_by == 'asc' else query.order_by(column_sorted.desc())
        # Default: sort by
        else:
            query = query.order_by(User.modified_date.desc())

        # 5. Paginator
        paginator = paginate(query, page_number, page_size)
        # 6. Dump data
        users = UserSchema(many=True).dump(paginator.items)

        response_data = dict(
            items=users,
            total_pages=paginator.pages,
            total=paginator.total
        )
        return send_result(data=response_data)
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('/<user_id>', methods=['GET'])
@authorization_require()
def get_user_by_id(user_id):
    """ This api get user by id
        Returns:
        Examples::
    """
    user = User.get_by_id(user_id)
    if user is None:
        return send_error(message='USER_NOT_EXISTED')
    user = UserSchema().dump(user)
    return send_result(data=user)
