import uuid
from flask import jsonify
from flask_jwt_extended import decode_token
from typing import List
import pickle
import json
from app.models import Token
from app.extensions import red, CONFIG
from app.utils import get_timestamp_now
from app.models import Message, db


def send_result(data: any = None, message_id: str = '', message: str = "OK", code: int = 200,
                status: str = 'success', show: bool = False, duration: int = 0, code_lang :str = 'EN',
                val_error: dict = {}, is_dynamic: bool = False):
    """
    Args:
        data: simple result object like dict, string or list
        message: message send to client, default = OK
        code: code default = 200
        version: version of api
    :param data:
    :param message_id:
    :param message:
    :param code:
    :param status:
    :param show:
    :param duration:
    :param code_lang:

    :return:
    json rendered sting result
    """
    message_dict = {
        "message_id": message_id,
        "text": message,
        "status": status,
        "show": show,
        "duration": duration,
        "dynamic": is_dynamic,
        "code_lang": code_lang
    }
    # message_obj: Message = Message.query.filter(Message.message_id == message_id, Message.code_lang == code_lang)
    message_redis = red.get(f"message:{message_id}-{code_lang}")
    if message_redis is not None:
        message_obj = json.loads(message_redis)
        if message_dict['dynamic'] == 0:
            message_dict['text'] = message_obj['message']
        else:
            if not message == 'OK':
                message_dict['text'] = message
            else:
                message_dict['text'] = message_obj['message'].format(**val_error)
        message_dict['status'] = message_obj['status']
        message_dict['show'] = message_obj['show']
        message_dict['duration'] = message_obj['duration']

    res = {
        "code": code,
        "data": data,
        "message": message_dict,
    }

    return jsonify(res), 200


def send_error(data: any = None, message_id: str = '', message: str = "Error", code: int = 200,
               status: str = 'error', show: bool = False, duration: int = 0, val_error: dict = {},
               is_dynamic: bool = False, code_lang: str = 'EN'):
    """

    :param data:
    :param message_id:
    :param message:
    :param code:
    :param status:
    :param show:
    :param duration:
    :param code_lang:
    :return:
    """
    message_dict = {
        "message_id": message_id,
        "text": message,
        "status": status,
        "show": show,
        "duration": duration,
        "dynamic": is_dynamic,
        "code_lang": code_lang
    }
    # message_obj = Message.query.filter(Message.message_id == message_id, Message.code_lang == code_lang)
    message_redis = red.get(f"message:{message_id}-{code_lang}")
    if message_redis is not None:
        message_obj = json.loads(message_redis)
        if message_dict['dynamic'] == 0:
            message_dict['text'] = message_obj['message']
        else:
            if not message == 'OK':
                message_dict['text'] = message
            else:
                message_dict['text'] = message_obj['message'].format(**val_error)
        message_dict['status'] = message_obj['status']
        message_dict['show'] = message_obj['show']
        message_dict['duration'] = message_obj['duration']
        message_dict['created_date'] = message_obj['created_date']
        message_dict['modified_date'] = message_obj['modified_date']
        message_dict['created_user'] = message_obj['created_user']
        message_dict['last_modified_user'] = message_obj['last_modified_user']

    res = {
        "code": code,
        "data": data,
        "message": message_dict,
        "version": get_version(CONFIG.VERSION)
    }

    return jsonify(res), code


def get_version(version: str) -> str:
    """
    if version = 1, return api v1
    version = 2, return api v2
    Returns:

    """
    version_text = f"Source Base APIs v{version}"
    return version_text


class RedisToken:
    @classmethod
    def add_token_to_database(cls, encoded_token: str, user_id: str):
        decoded_token = decode_token(encoded_token)
        jti = decoded_token['jti']
        time_expires = int(decoded_token['exp'])
        add_token = Token(id=str(uuid.uuid4()), user_id=user_id, jti=jti, encoded_token=encoded_token,
                          expires=time_expires)
        db.session.add(add_token)
        db.session.flush()
        db.session.commit()
        expires = int(time_expires - get_timestamp_now())
        tokens_jti = red.get(user_id)
        tokens_jti = tokens_jti.decode() + ',' + jti if tokens_jti else jti
        red.set(user_id, tokens_jti)
        red.set(jti, encoded_token, expires)

    @classmethod
    def revoke_token(cls, jti):
        block_token = Token.query.filter(Token.jti == jti).first()
        if block_token:
            block_token.is_block = 1
            db.session.commit()
        red.delete(jti)

    @classmethod
    def is_token_revoked(cls, decoded_token):
        """
        Checks if the given token is revoked or not. Because we are adding all the
        token that we create into this database, if the token is not present
        in the database we are going to consider it revoked, as we don't know where
        it was created.
        """
        jti = decoded_token['jti']
        is_revoked = False
        if red.get(jti) is None:
            is_revoked = True
        return is_revoked

    @classmethod
    def revoke_all_token(cls, user_id: str):
        db.session.query(Token).filter(Token.user_id == user_id).update({"is_block": 1})
        db.session.flush()
        db.session.commit()
        tokens_jti = red.get(user_id)
        tokens_jti = tokens_jti.decode() if tokens_jti else ''
        tokens_jti = tokens_jti.split(',')
        for jti in tokens_jti:
            red.delete(jti)
        red.set(user_id, '')

    @classmethod
    def add_list_permission(cls, user_id: str, list_permission: List[str]):
        permission_user = f"permission_{user_id}"
        red.set(permission_user, pickle.dumps(list_permission))


