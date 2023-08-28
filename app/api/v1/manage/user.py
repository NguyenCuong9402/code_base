import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL, ADMIN_GROUP, ADMIN_ROLE
from app.validator import UserSchema, GetUserValidation, UserValidation, ChangeUserValidation
from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import or_
from app.models import User, Group, UserGroupRole, Role, Permission
from app.api.helper import send_error, send_result, Token
from app.extensions import db, logger
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, normalize_search_input, escape_wildcard, \
    generate_password
from app.gateway import authorization_require
from marshmallow import ValidationError
import uuid

api = Blueprint('manage/user', __name__)


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
        query = query.filter(User.email != ADMIN_EMAIL)
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
    try:
        user = User.query.filter(User.id == user_id).first()
        if user is None:
            return send_error(message='USER_NOT_EXISTED')
        data = UserSchema().dump(user)
        return send_result(data=data)
    except Exception as ex:
        return send_error(str(ex))


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
        password = generate_password()

        new_user = User(
            id=str(uuid.uuid4()),
            created_date=get_timestamp_now(),
            modified_date=get_timestamp_now(),
            password_hash=generate_password_hash(password),
            email=json_req['email'],
            full_name=json_req['full_name'],
            type=2,
            created_user_id=user_create_id,
            last_modified_user_id=user_create_id,
            status=json_req['status'],
            force_change_password=1
        )
        db.session.add(new_user)

        list_user_role = [UserGroupRole(id=str(uuid.uuid4()), user_id=new_user.id, role=role.id) for role in roles]
        list_user_group = [UserGroupRole(id=str(uuid.uuid4()), user_id=new_user.id, group_id=group.id) for group in groups]
        db.session.bulk_save_objects(list_user_group)
        db.session.bulk_save_objects(list_user_role)
        db.session.add(new_user)
        db.session.commit()
        data = UserSchema().dump(new_user)
        data['password'] = password
        return send_result(data=data, message='Success')
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))


@api.route('/<user_id>', methods=['PUT'])
@authorization_require()
def put_user(user_id):
    try:
        try:
            json_req = request.get_json()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442)
        # trim input body
        json_body = trim_dict(json_req)
        # validate request body
        validator_input = ChangeUserValidation()
        is_not_validate = validator_input.validate(json_body)
        if is_not_validate:
            return send_error(data=is_not_validate, message='INVALID')
        user = User.query.filter(User.id == user_id, type != 3).first()
        is_active = json_req.get('is_active', None)
        group_ids = json_req.get('group_ids', None)
        role_ids = json_req.get('role_ids', None)

        if is_active is not None:
            user.is_active = is_active

        if group_ids is not None:
            UserGroupRole.query.filter(UserGroupRole.user_id == user_id, UserGroupRole.role_id.is_(None)).delete()
            groups = Group.query.filter(Role.key != ADMIN_GROUP, Group.id.in_(group_ids)).all()
            list_user_group = [UserGroupRole(id=str(uuid.uuid4()), group_id=group.id, user_id=user_id) for group in
                               groups]
            db.session.bulk_save_objects(list_user_group)
            db.session.flush()
            # logout
            Token.revoke_all_token(user.id)
        if role_ids is not None:
            UserGroupRole.query.filter(UserGroupRole.user_id == user_id, UserGroupRole.group_id.is_(None)).delete()

            roles = Role.query.filter(Role.key != ADMIN_ROLE, Role.id.in_(role_ids)).all()
            list_user_role = [UserGroupRole(id=str(uuid.uuid4()), user_id=user_id, role_id=role.id) for role in roles]
            db.session.bulk_save_objects(list_user_role)
            db.session.flush()
            # logout
            Token.revoke_all_token(user.id)
        user.last_modified_user_id = get_jwt_identity()
        db.session.commit()
        return send_result(message='CHANGE_SUCCESS')
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))


@api.route('/<user_id>', methods=['DELETE'])
@authorization_require()
def delete_user(user_id):
    try:
        user = User.query.filter(User.id == user_id, User.type != 3)
        if user is None:
            return send_error(message='NOT FOUND USER')
        db.session.delete(user)
        db.session.commit()
        # revoke all token of reset user  from database
        Token.revoke_all_token(user_id)
        return send_result(message='DELETE_SUCCESS')
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))




