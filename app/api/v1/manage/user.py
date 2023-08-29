import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL, ADMIN_GROUP, ADMIN_ROLE, MESSAGE_ID
from app.validator import UserSchema, GetUserValidation, UserValidation, ChangeUserValidation, DeleteUserValidator
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
    try:
        code_lang = request.args.get('code_lang', 'EN')
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
            return send_error(message='EXISTED_EMAIL', message_id=message_id, code_lang=code_lang)

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
        db.session.flush()
        groups_id = json_req.get("groups_id", [])
        roles_id = json_req.get("roles_id", [])
        if groups_id:
            groups = Group.query.filter(Group.id.in_(groups_id)).all()
            list_user_group = [UserGroupRole(id=str(uuid.uuid4()), user_id=new_user.id, group_id=group.id) for group in
                               groups]
            db.session.bulk_save_objects(list_user_group)
        if roles_id:
            roles = Role.query.filter(Role.id.in_(roles_id)).all()
            list_user_role = [UserGroupRole(id=str(uuid.uuid4()), user_id=new_user.id, role_id=role.id) for role in roles]
            db.session.bulk_save_objects(list_user_role)
        db.session.commit()
        data = UserSchema().dump(new_user)
        data['password'] = password
        return send_result(data=data, message='Success', code_lang=code_lang, message_id=MESSAGE_ID)
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))


@api.route('/<user_id>', methods=['PUT'])
@authorization_require()
def put_user(user_id):
    try:
        code_lang = request.args.get('code_lang', 'EN')

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
        if user is None:
            return send_error(message='Not found user.')
        is_active = json_req.get('is_active', None)
        groups_id = json_req.get('groups_id', None)
        roles_id = json_req.get('roles_id', None)
        status = json_req.get('status', None)
        user_groups = UserGroupRole.query.filter(UserGroupRole.user_id == user_id, UserGroupRole.role_id.is_(None))
        user_groups_id = [group.group_id for group in user_groups.all()]

        user_roles = UserGroupRole.query.filter(UserGroupRole.user_id == user_id, UserGroupRole.group_id.is_(None))
        user_roles_id = [role.role_id for role in user_roles.all()]
        flag_change = False
        if is_active is not None and is_active != user.is_active:
            user.is_active = is_active
            flag_change = True
        if status is not None and status != user.status:
            user.status = status
            flag_change = True
        if groups_id is not None and groups_id != user_groups_id:
            user_groups.delete()
            groups = Group.query.filter(Group.key != ADMIN_GROUP, Group.id.in_(groups_id)).all()
            list_user_group = [UserGroupRole(id=str(uuid.uuid4()), group_id=group.id, user_id=user_id) for group in
                               groups]
            db.session.bulk_save_objects(list_user_group)
            db.session.flush()
            flag_change = True
        if roles_id is not None and roles_id != user_roles_id:
            user_roles.delete()
            roles = Role.query.filter(Role.key != ADMIN_ROLE, Role.id.in_(roles_id)).all()
            list_user_role = [UserGroupRole(id=str(uuid.uuid4()), user_id=user_id, role_id=role.id) for role in roles]
            db.session.bulk_save_objects(list_user_role)
            db.session.flush()
            flag_change = True
        # Revoke all tokens
        if flag_change:
            Token.revoke_all_token(user.id)
            user.last_modified_user_id = get_jwt_identity()
            db.session.commit()
            return send_result(message='CHANGE_SUCCESS', message_id=MESSAGE_ID, code_lang=code_lang)
        return send_result(message='NOTHING CHANGED')
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))


@api.route('', methods=['DELETE'])
@authorization_require()
def delete_user():
    try:

        code_lang = request.args.get('code_lang', 'EN')

        try:
            body = request.get_json()
            body_request = DeleteUserValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        users_id = body_request.get("users_id")
        users = User.query.filter(User.id.in_(users_id), User.type != 3)
        for user in users.all():
            Token.revoke_all_token(user.id)
        users.delete()
        db.session.commit()
        return send_result(message='DELETE_SUCCESS', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))




