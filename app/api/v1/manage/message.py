import json
from sqlalchemy_pagination import paginate
from werkzeug.security import generate_password_hash

from app.enums import ADMIN_EMAIL, ADMIN_GROUP, ADMIN_ROLE, MESSAGE_ID
from app.validator import MessageSchema, GetMessageValidation, DeleteMessageValidator, MessageValidation, \
    UpdateMessageValidator
from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import or_
from app.models import User, Group, UserGroupRole, Role, Permission, Message
from app.api.helper import send_error, send_result, Token
from app.extensions import db, logger
from app.utils import trim_dict, get_timestamp_now, data_preprocessing, normalize_search_input, escape_wildcard, \
    generate_password
from app.gateway import authorization_require
from marshmallow import ValidationError
from app.pubsub_manager import publish_add_message, publish_remove_message, publish_update_message
import uuid


api = Blueprint('manage/message', __name__)


@api.route('/<message_id>', methods=['GET'])
@authorization_require()
def get_message_by_id(message_id):
    """ This api get user by id
        Returns:
        Examples::
    """
    try:
        message = Message.query.filter(Message.id == message_id).first()
        if message is None:
            return send_error(message='MESSAGE_NOT_EXISTED')
        data = MessageSchema().dump(message)
        return send_result(data=data)
    except Exception as ex:
        return send_error(str(ex))


@api.route('', methods=['GET'])
@authorization_require()
def get_messages():
    try:
        """ This api get all user.
            Returns:
            Examples::
        """
        # 1. validate request parameters
        try:
            params = request.args
            params = GetMessageValidation().load(params) if params else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID_PARAMETERS_ERROR', data=err.messages)

        # 2. Process input
        page_number = params.get('page', 1)
        page_size = params.get('page_size', 15)
        search = params.get('search', None)
        sort = params.get('sort', None)
        order_by = params.get('order_by', 'desc')

        search = normalize_search_input(search)
        # 3. Query
        query = Message.query
        if search:
            text_like = "%{}%".format(escape_wildcard(search.strip()))
            query = query.filter(Message.message.collate('utf8mb4_bin').ilike(text_like))
        # 4. Sort by column
        if sort:
            column_sorted = getattr(Message, sort)
            query = query.order_by(column_sorted.asc()) if order_by == 'asc' else query.order_by(column_sorted.desc())
        # Default: sort by
        else:
            query = query.order_by(Message.modified_date.desc())

        # 5. Paginator
        paginator = paginate(query, page_number, page_size)
        # 6. Dump data
        messages = MessageSchema(many=True).dump(paginator.items)

        response_data = dict(
            items=messages,
            total_pages=paginator.pages,
            total=paginator.total
        )
        return send_result(data=response_data)
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('', methods=['DELETE'])
@authorization_require()
def delete_message():
    try:
        code_lang = request.args.get('code_lang', 'EN')
        try:
            body = request.get_json()
            body_request = DeleteMessageValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)
        messages_id = body_request.get("messages_id")
        messages = Message.query.filter(Message.id.in_(messages_id))
        message_key = [f"message:{message.message_id}-{message.code_lang}" for message in messages.all()]
        messages.delete()
        db.session.flush()
        db.session.commit()
        publish_remove_message(message_key)
        return send_result(message='DELETE_SUCCESS', message_id=MESSAGE_ID, code_lang=code_lang)
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))


@api.route('', methods=['POST'])
@authorization_require()
def create_message():
    try:
        code_lang = request.args.get('code_lang', 'EN')

        user_create_id = get_jwt_identity()
        try:
            body = request.get_json()
            body_request = MessageValidation().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)

        check_exits_message = Message.query.filter(Message.message_id == body_request.get('message_id'),
                                                   Message.code_lang == body_request.get("code_lang")).first()
        if check_exits_message:
            return send_error(message='EXISTED', code_lang=code_lang)

        body_request['id'] = str(uuid.uuid4())
        body_request['created_user'] = user_create_id
        body_request['last_modified_user'] = user_create_id
        new_message = Message(**body_request)
        db.session.add(new_message)
        db.session.flush()
        db.session.commit()
        key = f"message:{new_message.message_id}-{new_message.code_lang}"
        data = MessageSchema(only=["id", "message_id", "description", "show", "dynamic", "duration", "status",
                                   "message", "object", "code_lang", "last_modified_user", "created_date",
                                   "created_user", "modified_date"]).dump(new_message)
        publish_add_message(key, data)
        return send_result(data=MessageSchema().dump(new_message), message='Success', code_lang=code_lang,
                           message_id="m123")
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


@api.route('/<message_id>', methods=['PUT'])
@authorization_require()
def update_message(message_id):
    try:
        code_lang = request.args.get('code_lang', 'EN')
        try:
            body = request.get_json()
            body_request = UpdateMessageValidator().load(body) if body else dict()
        except ValidationError as err:
            logger.error(json.dumps({
                "message": err.messages,
                "data": err.valid_data
            }))
            return send_error(message='INVALID', data=err.messages)

        message = Message.query.filter(Message.id == message_id).first()
        message_key = f"message:{message.message_id}-{message.code_lang}"
        if message is None:
            return send_error(message='Not found message')

        for key in body_request.keys():
            message.__setattr__(key, body_request[key])
        db.session.flush()
        db.session.commit()
        data = MessageSchema(only=["id", "message_id", "description", "show", "dynamic", "duration", "status",
                                   "message", "object", "code_lang", "last_modified_user", "created_date",
                                   "created_user", "modified_date"]).dump(message)
        publish_update_message(message_key, data)
        return send_result(code_lang=code_lang, message_id=MESSAGE_ID, message='Success')
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))


