import json
import os
import uuid

import pandas as pd
from flask import Flask

from app.api.v1.manage.role import convert_method_by_type
from app.models import Message, User, Role, Group, UserGroupRole, Permission, RolePermission
from app.extensions import db
from app.settings import DevConfig

CONFIG = DevConfig


class Worker:
    def __init__(self):
        app = Flask(__name__)
        app.config.from_object(CONFIG)
        db.app = app
        db.init_app(app)
        app_context = app.app_context()
        app_context.push()

    def import_message(self):
        file_name = "import_message.xlsx"
        # import permission
        df = pd.read_excel(file_name, sheet_name='message')
        list_add_message = []
        # Lặp qua từng hàng của DataFrame và thêm vào cơ sở dữ liệu
        for index, row in df.iterrows():
            message = Message.query.filter(Message.code_lang == row['code_lang'], Message.message_id == row['message_id'])
            if message is None:
                message = Message(
                    id=str(uuid.uuid4()),
                    message_id=row['message_id'],
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


if __name__ == '__main__':
    print("=" * 10, f"Starting update rbac to the database on the uri: {CONFIG.SQLALCHEMY_DATABASE_URI}", "=" * 10)
    worker = Worker()
    worker.import_message()
    print("=" * 50, "update rbac", "=" * 50)