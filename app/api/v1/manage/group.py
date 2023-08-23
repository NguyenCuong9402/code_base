import json
from sqlalchemy_pagination import paginate
from app.enums import ADMIN_GROUP, ADMIN_ROLE
from app.validator import GetGroupValidation, GroupSchema, DeleteGroupValidator, PostGroupValidator, UpdateGroupValidator
from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity
from app.models import Group, UserGroupRole, Role
from app.api.helper import send_error, send_result
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


@api.route('', methods=['DELETE'])
@authorization_require()
def remove_groups():
    try:
        try:
            body = request.get_json()
            body_request = DeleteGroupValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        group_ids = body_request.get('group_ids', [])
        is_delete_all = body_request.get('is_delete_all', False)
        Group.query.filter(Group.id.in_(group_ids), Group.key != ADMIN_GROUP).delete() if is_delete_all \
            else Group.query.filter(Group.id.notin_(group_ids), Group.key != ADMIN_GROUP).delete()
        db.session.flush()
        db.session.commit()
        return send_result(message='Remove success!')
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('', methods=['POST'])
@authorization_require()
def post_group():
    try:
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
        return send_result(message='Add Group success!')
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('/<group_id>', methods=['PUT'])
@authorization_require()
def update_group(group_id):
    try:
        user_id = get_jwt_identity()
        try:
            body = request.get_json()
            body_request = UpdateGroupValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        name = body_request.get('name', None)
        description = body_request.get('description', None)
        group = Group.query.filter(Group.id == group_id, Group.key != ADMIN_GROUP).first()
        if group is None:
            return send_error(message='NOT FOUND GROUP')
        if name is not None:
            group.name = name
        if description is not None:
            group.description = description
        group.last_modified_user = user_id
        group.modified_date = get_timestamp_now()
        db.session.flush()

        UserGroupRole.query.filter(UserGroupRole.group_id == group.id, UserGroupRole.user_id.is_(None)).delete()

        role_ids = body_request.get('role_ids', [])
        roles = Role.query.filter(Role.key != ADMIN_ROLE, Role.id.in_(role_ids)).all()
        list_group_role = [UserGroupRole(id=str(uuid.uuid4()), group_id=group.id, role_id=role.id) for role in roles]
        db.session.bulk_save_objects(list_group_role)
        db.session.flush()

        db.session.commit()
        return send_result(message='Update success!')
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))
