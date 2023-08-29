import pandas as pd

from flask import Blueprint, request
from sqlalchemy import or_
from app.models import Permission, Message
from app.api.helper import send_error, send_result
from app.extensions import db
from app.enums import MESSAGE_ID
from app.gateway import authorization_require
import uuid

api = Blueprint('manage/import_file', __name__)


@api.route('/upload', methods=['POST'])
def upload_file():
    try:
        code_lang = request.args.get('code_lang', 'EN')

        file = request.files['file']
        if file:
            # Đọc dữ liệu từ tệp Excel bằng pandas
            df = pd.read_excel(file)
            list_add_permission = []
            # Lặp qua từng hàng của DataFrame và thêm vào cơ sở dữ liệu
            for index, row in df.iterrows():
                existing_permission = Permission.query.filter(Permission.key == row['key'],
                                                              Permission.name == row['name'],
                                                              Permission.resource == row['resource']).first()
                if existing_permission is None:
                    permission = Permission(
                        id=str(uuid.uuid4()),
                        key=row['key'],
                        name=row['name'],
                        resource=row['resource']
                    )
                    list_add_permission.append(permission)
            db.session.bulk_save_objects(list_add_permission)
            db.session.commit()
            return send_result(message="File uploaded and data imported successfully.", code_lang=code_lang,
                               message_id=MESSAGE_ID)
        return send_error(message="No file uploaded.")
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))


@api.route('/upload_message', methods=['POST'])
@authorization_require()
def upload_file_message():
    try:
        code_lang = request.args.get('code_lang', 'EN')

        file = request.files['file']
        if file:
            # Đọc dữ liệu từ tệp Excel bằng pandas
            df = pd.read_excel(file)
            list_add_message = []
            # Lặp qua từng hàng của DataFrame và thêm vào cơ sở dữ liệu
            for index, row in df.iterrows():
                message = Message.query.filter(Message.code_lang == row['code_lang'], Message.id == row['id'])
                if message is None:
                    message = Message(
                        id=row['id'],
                        description=row['description'],
                        show=row['show'],
                        duration=row['duration'],
                        status=row['status'],
                        message=row['message'],
                        dynamic=row['dynamic'],
                        object=row['object'],
                        code_lang=row['code_lang']

                    )
                    list_add_message.append(message)
            db.session.bulk_save_objects(list_add_message)
            db.session.commit()
            return send_result(message="File uploaded and data imported successfully.", code_lang=code_lang,
                               message_id=MESSAGE_ID)
        return send_error(message="No file uploaded.", code_lang=code_lang, message_id=MESSAGE_ID)
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))

