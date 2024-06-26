import json
from sqlalchemy_pagination import paginate

from app.api.v1.manage.group import get_users_id_by_group_and_role
from app.enums import ADMIN_ROLE, MESSAGE_ID
from app.validator import GetRoleValidation, RoleSchema, DeleteRoleValidator, UpdateRoleValidator, PostRoleValidator
from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity
from app.models import Group, Role, Permission, RolePermission
from app.api.helper import send_error, send_result, RedisToken
from app.extensions import db, logger
from app.utils import normalize_search_input, escape_wildcard
from app.gateway import authorization_require
from marshmallow import ValidationError
import uuid
from sqlalchemy import or_, distinct

api = Blueprint('manage/role', __name__)


@api.route('/get-key-permission', methods=['GET'])
@authorization_require()
def get_key_permission():
    try:
        unique_keys_query = db.session.query(distinct(Permission.key)).filter(Permission.key != ADMIN_ROLE)
        unique_keys = [result[0] for result in unique_keys_query.all()]
        return send_result(data=unique_keys, message='Ok')
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('/<role_id>', methods=['GET'])
@authorization_require()
def get_role(role_id):
    try:
        code_lang = request.args.get('code_lang', 'EN')
        query = Role.query.filter(Role.key != ADMIN_ROLE, Role.id == role_id).first()
        return send_result(data=RoleSchema().dump(query), message='Success', message_id=MESSAGE_ID,
                           code_lang=code_lang)
    except Exception as ex:
        return send_error(message=str(ex))


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
        code_lang = request.args.get('code_lang', 'EN')

        try:
            body = request.get_json()
            body_request = DeleteRoleValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)

        roles_id = body_request.get('roles_id', [])
        is_delete_all = body_request.get('is_delete_all', True)

        if is_delete_all:
            users_id = get_users_id_by_group_and_role(groups_id=[], roles_id=roles_id)
            Role.query.filter(Role.id.in_(roles_id), Role.key != ADMIN_ROLE).delete()
        else:
            query_role = Role.query.filter(Role.id.notin_(roles_id), Role.key != ADMIN_ROLE)
            roles_id_to_delete = [role.id for role in query_role.all()]
            users_id = get_users_id_by_group_and_role(groups_id=[], roles_id=roles_id_to_delete)
            query_role.delete()
        db.session.flush()
        # Clear token
        for user_id in users_id:
            RedisToken.revoke_all_token(user_id)

        db.session.commit()
        return send_result(message='Remove success!', code_lang=code_lang, message_id=MESSAGE_ID)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('', methods=['POST'])
@authorization_require()
def create_roles():
    try:
        code_lang = request.args.get('code_lang', 'EN')

        try:
            body = request.get_json()
            body_request = PostRoleValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        key = body_request.get('key')
        check_key = Permission.query.filter(Permission.key == key, Permission.key != ADMIN_ROLE)
        if check_key is None:
            return send_error(message='Key does not exist!', code_lang=code_lang, message_id=MESSAGE_ID)
        name = body_request.get('name')
        check_name = Role.query.filter(Role.name == name).first()
        if check_name:
            return send_error(message='Name already exists', code_lang=code_lang)
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

        role_type = body_request.get('role_type')
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
        return send_result(message='Created success!', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('/<role_id>', methods=['PUT'])
@authorization_require()
def update_role(role_id):
    try:
        last_modified_user = get_jwt_identity()
        code_lang = request.args.get('code_lang', 'EN')
        try:
            body = request.get_json()
            body_request = UpdateRoleValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        role = Role.query.filter(Role.id == role_id).first()
        if role is None:
            return send_error(message='Not found role')

        role_type = body_request.get('type', None)
        if role_type is not None and (role_type != role.type):
            RolePermission.query.filter(RolePermission.role_id == role.id).delete()
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
            users_id = get_users_id_by_group_and_role(groups_id=[], roles_id=[role.id])
            # Clear token
            for user_id in users_id:
                RedisToken.revoke_all_token(user_id)
        for key in body_request.keys():
            role.__setattr__(key, body_request[key])
        role.last_modified_user = last_modified_user
        db.session.flush()
        db.session.commit()
        return send_result(code_lang=code_lang, message_id=MESSAGE_ID, message='Success')
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
