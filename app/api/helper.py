import uuid
from flask import jsonify
from flask_jwt_extended import decode_token
from typing import List
import pickle

from app.extensions import red
from app.utils import get_timestamp_now
from app.models import Message, TokenModel, db


def send_result(data: any = None, message_id: str = '', message: str = "OK", code: int = 200,
                status: str = 'success', show: bool = False, duration: int = 0,
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
    :return:
    json rendered sting result
    """
    message_dict = {
        "id": message_id,
        "text": message,
        "status": status,
        "show": show,
        "duration": duration,
        "dynamic": is_dynamic
    }
    message_obj: Message = Message.query.get(message_id)
    if message_obj:
        if message_dict['dynamic'] == 0:
            message_dict['text'] = message_obj.message
        else:
            if not message == 'OK':
                message_dict['text'] = message
            else:
                message_dict['text'] = message_obj.message.format(**val_error)
        message_dict['status'] = message_obj.status
        message_dict['show'] = message_obj.show
        message_dict['duration'] = message_obj.duration

    res = {
        "code": code,
        "data": data,
        "message": message_dict,
    }

    return jsonify(res), 200


def send_error(data: any = None, message_id: str = '', message: str = "Error", code: int = 200,
               status: str = 'error', show: bool = False, duration: int = 0,
               val_error: dict = {}, is_dynamic: bool = False):
    """

    :param data:
    :param message_id:
    :param message:
    :param code:
    :param status:
    :param show:
    :param duration:
    :return:
    """
    message_dict = {
        "id": message_id,
        "text": message,
        "status": status,
        "show": show,
        "duration": duration,
        "dynamic": is_dynamic
    }
    message_obj = Message.query.get(message_id)
    if message_obj:
        if message_dict['dynamic'] == 0:
            message_dict['text'] = message_obj.message
        else:
            if not message == 'Error':
                message_dict['text'] = message
            else:
                message_dict['text'] = message_obj.message.format(**val_error)

        message_dict['status'] = message_obj.status
        message_dict['show'] = message_obj.show
        message_dict['duration'] = message_obj.duration

    res = {
        "code": code,
        "data": data,
        "message": message_dict,
        # "version": get_version(CONFIG.VERSION)
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


class Token:
    @classmethod
    def add_token_to_database(cls, encoded_token: str, user_id: str):
        decoded_token = decode_token(encoded_token)
        jti = decoded_token['jti']
        expires = int(decoded_token['exp'] - get_timestamp_now())

        tokens_jti = red.get(user_id)
        tokens_jti = tokens_jti.decode() + ',' + jti if tokens_jti else jti
        red.set(user_id, tokens_jti)
        red.set(jti, encoded_token, expires)
        # add_jti = TokenModel(
        #     id=str(uuid.uuid4()),
        #     user_id=user_id,
        #     jti=jti,
        #     expires=expires,
        #     encoded_token=encoded_token)
        # db.session.add(add_jti)
        # db.session.flush()
        # db.session.commit()

    @classmethod
    def revoke_token(cls, jti):
        red.delete(jti)
        # TokenModel.query.filter(TokenModel.jti == jti).delete()
        # db.session.flush()
        # db.session.commit()

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
        # jti = decoded_token['jti']
        # is_revoked = False
        # get_jti = TokenModel.query.filter(TokenModel.jti == jti, TokenModel.expires > get_timestamp_now()).first()
        # if get_jti is None:
        #     is_revoked = True
        # return is_revoked

    @classmethod
    def revoke_all_token(cls, user_id: str):
        # TokenModel.query.filter(TokenModel.user_id == user_id).delete()
        # db.session.flush()
        # db.session.commit()
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


