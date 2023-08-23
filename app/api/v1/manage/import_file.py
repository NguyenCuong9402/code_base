import pandas as pd

from flask import Blueprint, request
from sqlalchemy import or_
from app.models import Permission
from app.api.helper import send_error, send_result
from app.extensions import db

from app.gateway import authorization_require
import uuid

api = Blueprint('manage/import_file', __name__)


@api.route('/upload', methods=['POST'])
@authorization_require()
def upload_file():
    try:
        file = request.files['file']
        if file:
            # Đọc dữ liệu từ tệp Excel bằng pandas
            df = pd.read_excel(file)
            list_add_permission = []
            # Lặp qua từng hàng của DataFrame và thêm vào cơ sở dữ liệu
            for index, row in df.iterrows():
                existing_permission = Permission.query.filter(or_(Permission.key == row['key'],
                                                                  Permission.name == row['name']),
                                                              Permission.resource == row['resource'])
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
            return send_result(message="File uploaded and data imported successfully.")
        else:
            return send_error(message="No file uploaded.")
    except Exception as e:
        db.session.rollback()
        return send_error(message=str(e))
