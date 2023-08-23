import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL, ADMIN_ROLE
from app.validator import UserSchema, GetUserValidation, UserValidation, UserSettingSchema, ChangeUserValidation, \
    GetRoleValidation, RoleSchema, DeleteRoleValidator, UpdateRoleValidator
from flask import Blueprint, request
from flask_jwt_extended import (get_jwt_identity, get_raw_jwt, jwt_refresh_token_required, jwt_required)
from sqlalchemy import or_, func, distinct
from app.models import User, Group, UserGroupRole, Role, Permission, UserSetting, RolePermission
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
def get_roles():
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


@api.route('', methods=['DELETE'])
@authorization_require()
def remove_roles():
    try:
        try:
            body = request.get_json()
            body_request = DeleteRoleValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)

        role_ids = body_request.get('role_ids', [])
        is_delete_all = body_request.get('is_delete_all', False)
        Role.query.filter(Role.id.in_(role_ids), Group.key != ADMIN_ROLE).delete() if is_delete_all \
            else Role.query.filter(Role.id.notin_(role_ids), Group.key != ADMIN_ROLE).delete()
        db.session.flush()
        db.session.commit()
        return send_result(message='Remove success!')
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('', methods=['POST'])
@authorization_require()
def create_roles():
    try:
        try:
            body = request.get_json()
            body_request = DeleteRoleValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        key = body_request.get('key')
        check_key = Permission.query.filter(Permission.key == key, Permission.key != ADMIN_ROLE)
        if check_key is None:
            return send_error(message='Key does not exist!')
        name = body_request.get('name')
        check_name = Role.query.filter(Role.name == name)
        if check_name is not None:
            return send_error(message='Name already exists')
        description = body_request.get('description', '')
        role = Role(
            id=str(uuid.uuid4()),
            key=key,
            name=name,
            description=description,
            created_user=get_jwt_identity(),
            last_modified_user=get_jwt_identity()
        )
        db.session.add(role)
        db.session.flush()

        role_type = body_request.get('type')
        list_method = convert_method_by_type(role_type)
        permission_data = []
        for item in list_method:
            result = Permission.query.filter(Permission.key == key,
                                             Permission.resource.ilike(f'%{item}%')).all()
            permission_data.extend(result)
        if permission_data:
            list_role_permission = [RolePermission(id=str(uuid.uuid1()), permission_id=permission.id, role_id=role.id)
                                    for permission in permission_data]
            db.session.bulk_save_objects(list_role_permission)

        db.session.flush()
        db.session.commit()
        return send_result(message='Created success!')
    except Exception as ex:
        db.session.rollback()
        return send_result(message=str(ex))


@api.route('/<role_id>', methods=['PUT'])
@authorization_require()
def post_role(role_id):
    try:
        try:
            body = request.get_json()
            body_request = UpdateRoleValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        role_type = body_request.get('type', None)
        role = Role.query.filter(Role.id == role_id)
        for key in body_request.keys():
            role.__setattr__(key, body_request[key])
        if role_type is not None:
            Permission.query.filter(Permission.role_id == role.id).delete()
            list_method = convert_method_by_type(role_type)
            permission_data = []
            for item in list_method:
                result = Permission.query.filter(Permission.key == role.key,
                                                 Permission.resource.ilike(f'%{item}%')).all()
                permission_data.extend(result)
            if permission_data:
                list_role_permission = [RolePermission(id=str(uuid.uuid1()), permission_id=permission.id,
                                                       role_id=role.id) for permission in permission_data]
                db.session.bulk_save_objects(list_role_permission)
        db.session.flush()
        db.session.commit()
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


def convert_method_by_type(role_type):
    number_binary = int(role_type)
    number_binary = f'{number_binary:04b}'

    list_method = []
    if int(number_binary[0]) == 1:
        list_method.append("delete@/")
    if int(number_binary[1]) == 1:
        list_method.append("put@/")
    if int(number_binary[2]) == 1:
        list_method.append("post@/")
    if int(number_binary[3]) == 1:
        list_method.append("get@/")

    return list_method
