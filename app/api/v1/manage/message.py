import pandas as pd

from flask import Blueprint, request
from sqlalchemy import or_
from app.models import Permission, Message
from app.api.helper import send_error, send_result
from app.extensions import db
from app.enums import MESSAGE_ID
from app.gateway import authorization_require
import uuid
from app.validator import MessageSchema


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