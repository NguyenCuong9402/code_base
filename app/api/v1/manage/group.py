import json
from sqlalchemy_pagination import paginate
from app.enums import ADMIN_GROUP, ADMIN_ROLE, MESSAGE_ID
from app.validator import GetGroupValidation, GroupSchema, DeleteGroupValidator, PostGroupValidator, \
    UpdateGroupValidator
from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity
from app.models import Group, UserGroupRole, Role
from app.api.helper import send_error, send_result, RedisToken
from app.extensions import db, logger
from app.utils import get_timestamp_now, normalize_search_input, escape_wildcard
from app.gateway import authorization_require
from marshmallow import ValidationError
import uuid

api = Blueprint('manage/group', __name__)


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
            params = GetGroupValidation().load(params) if params else dict()
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
        query = Group.query
        query = query.filter(Group.key != ADMIN_GROUP)

        if search_name:
            text_like = "%{}%".format(escape_wildcard(search_name.strip()))
            query = query.filter(Group.name.ilike(text_like))

        # 4. Sort by column
        if sort:
            column_sorted = getattr(Group, sort)
            query = query.order_by(column_sorted.asc()) if order_by == 'asc' else query.order_by(column_sorted.desc())
        # Default: sort by
        else:
            query = query.order_by(Group.modified_date.desc())

        # 5. Paginator
        paginator = paginate(query, page_number, page_size)
        # 6. Dump data
        groups = GroupSchema(many=True).dump(paginator.items)

        response_data = dict(
            items=groups,
            total_pages=paginator.pages,
            total=paginator.total
        )
        return send_result(data=response_data)
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('/<group_id>', methods=['GET'])
@authorization_require()
def get_group(group_id):
    try:
        code_lang = request.args.get('code_lang', 'EN')
        query = Group.query.filter(Group.key != ADMIN_GROUP, Group.id == group_id).first()
        return send_result(data=GroupSchema().dump(query), message='Success', message_id=MESSAGE_ID,
                           code_lang=code_lang)
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('', methods=['DELETE'])
@authorization_require()
def remove_groups():
    try:
        code_lang = request.args.get('code_lang', 'EN')
        try:
            body = request.get_json()
            body_request = DeleteGroupValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        groups_id = body_request.get('groups_id', [])
        is_delete_all = body_request.get('is_delete_all', True)
        if is_delete_all:
            users_id = get_users_id_by_group_and_role(groups_id=groups_id, roles_id=[])
            Group.query.filter(Group.id.in_(groups_id), Group.key != ADMIN_GROUP).delete()

        else:
            query_group = Group.query.filter(Group.id.notin_(groups_id), Group.key != ADMIN_GROUP)
            groups_id_to_delete = [role.id for role in query_group.all()]

            users_id = get_users_id_by_group_and_role(groups_id=groups_id_to_delete, roles_id=[])
            query_group.delete()

        # clear token
        for user_id in users_id:
            RedisToken.revoke_all_token(user_id)
        db.session.flush()
        db.session.commit()
        return send_result(message='Remove success!', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('', methods=['POST'])
@authorization_require()
def post_group():
    try:
        code_lang = request.args.get('code_lang', 'EN')
        user_id = get_jwt_identity()
        try:
            body = request.get_json()
            body_request = PostGroupValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        key = body_request.get('key')
        name = body_request.get('name')
        description = body_request.get('description', '')
        role_ids = body_request.get('role_ids', [])
        roles = Role.query.filter(Role.key != ADMIN_ROLE, Role.id.in_(role_ids)).all()
        group = Group(
            id=str(uuid.uuid4()),
            key=key,
            name=name,
            description=description,
            created_user=user_id,
            last_modified_user=user_id
        )
        db.session.add(group)
        db.session.flush()

        list_group_role = [UserGroupRole(id=str(uuid.uuid4()), group_id=group.id, role_id=role.id) for role in roles]
        db.session.bulk_save_objects(list_group_role)

        db.session.flush()
        db.session.commit()
        return send_result(message='Add Group success!', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('/<group_id>', methods=['PUT'])
@authorization_require()
def update_group(group_id):
    try:
        code_lang = request.args.get('code_lang', 'EN')
        last_modified_user = get_jwt_identity()
        try:
            body = request.get_json()
            body_request = UpdateGroupValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        group = Group.query.filter(Group.id == group_id, Group.key != ADMIN_GROUP).first()
        if group is None:
            return send_error(message='NOT FOUND GROUP')

        roles_id = body_request.pop('roles_id', None)
        group_roles = UserGroupRole.query.filter(UserGroupRole.group_id == group.id, UserGroupRole.user_id.is_(None))
        group_roles_id = [group_role.role_id for group_role in group_roles.all()]
        if roles_id is not None and roles_id != group_roles_id:
            users = get_users_id_by_group_and_role(groups_id=[group_id], roles_id=[])
            for user in users:
                RedisToken.revoke_all_token(user)
            group_roles.delete()
            roles = Role.query.filter(Role.key != ADMIN_ROLE, Role.id.in_(roles_id)).all()
            list_group_role = [UserGroupRole(id=str(uuid.uuid4()), group_id=group.id, role_id=role.id) for role in
                               roles]
            db.session.bulk_save_objects(list_group_role)
            db.session.flush()
        for key in body_request.keys():
            group.__setattr__(key, body_request[key])
        group.last_modified_user = last_modified_user
        group.modified_date = get_timestamp_now()
        db.session.flush()
        db.session.commit()
        return send_result(message='Update success!', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


def get_users_id_by_group_and_role(groups_id: list, roles_id: list):
    users_id = []
    if groups_id:
        query_users_group = UserGroupRole.query.filter(UserGroupRole.group_id.in_(groups_id),
                                                       UserGroupRole.role_id.is_(None)).all()
        users_id += [user.user_id for user in query_users_group]
    if roles_id:
        query_users_role = UserGroupRole.query.filter(UserGroupRole.role_id.in_(roles_id),
                                                      UserGroupRole.group_id.is_(None)).all()
        users_id += [user.user_id for user in query_users_role]
    return users_id
