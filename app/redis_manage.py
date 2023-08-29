import json

from .api import v1 as api_v1
from flask import Flask
from flask_cors import CORS
from .models import Message
from .api.helper import send_result, send_error
from .extensions import jwt, db, migrate, CONFIG, red


def add_messages_to_redis():
    messages = Message.query.all()
    for message in messages:
        key = f"message:{message.message_id}-{message.code_lang}"
        value = {
            "id": message.id,
            "message_id": message.message_id,
            "show": message.show,
            "description": message.description,
            "duration": message.duration,
            "status": message.status,
            "dynamic": message.dynamic,
            "object": message.object,
            "message": message.message,
            "code_lang": message.code_lang,
            "created_date": message.created_date,
            "modified_date": message.modified_date,
            "created_user": message.created_user,
            "last_modified_user": message.last_modified_user
        }
        red.set(key, json.dumps(value))

