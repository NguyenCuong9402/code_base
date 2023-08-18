import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL
from app.validator import UserSchema, GetUserValidation, UserValidation
from flask import Blueprint, request
from flask_jwt_extended import (get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)
from sqlalchemy import or_, func, distinct
from app.models import User, Group, UserGroupRole, Role, Permission
from app.api.helper import send_error, send_result
from app.extensions import jwt, db, logger
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, REGEX_VALID_PASSWORD, REGEX_EMAIL, \
    normalize_search_input, escape_wildcard, generate_password
from app.gateway import authorization_require
from marshmallow import ValidationError
import uuid

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


@api.route('', methods=['POST'])
@authorization_require()
def create_user():
    """ This is api for the user management registers user admin.

        Request Body:

        Returns:

        Input Examples:
        {
            "full_name": "Nguyễn Hữu Tiến",
            "email": "test6@gmail.com",
            "academic_rank": 1,
            "degree": 1,
            "regency": 3,
            "is_party_committee": 1,
            "is_faculty_office": 1,
            "role_party_committee": 1,
            "status": 1,
            "group_id": "6d9fd6ee-2461-11ec-9621-0242ac160001",
            "department_id": "1"
        }
    """
    try:
        try:
            json_req = request.get_json()
            user_create_id = get_jwt_identity()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442)

        # validate request body
        is_valid, message_id = data_preprocessing(cls_validator=UserValidation, input_json=json_req)
        if not is_valid:
            return send_error(message_id=message_id)
        check_exits_user = User.query.filter_by(email=json_req["email"]).first()

        if check_exits_user:
            return send_error(message='EXISTED_EMAIL')

        groups = Group.query.filter(Group.id.in_(json_req.get("group_ids", []))).all()
        roles = Role.query.filter(Role.id.in_(json_req.get("role_ids", []))).all()
        # create user
        user_id = str(uuid.uuid4())
        new_user = User()
        for key in json_req.keys():
            new_user.__setattr__(key, json_req[key])

        new_user.id = user_id
        new_user.created_user_id = user_create_id
        new_user.last_modified_user_id = user_create_id
        new_user.created_date = get_timestamp_now()
        new_user.modified_date = get_timestamp_now()

        password = generate_password()
        new_user.password = password
        new_user.password_hash = generate_password_hash(password)
        list_user_role = [UserGroupRole(id=str(uuid.uuid4()), user_id=user_id, role=role.id) for role in roles]
        list_user_group = [UserGroupRole(id=str(uuid.uuid4()), user_id=user_id, group_id=group.id) for group in groups]
        db.session.bulk_save_objects(list_user_group)
        db.session.bulk_save_objects(list_user_role)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))
