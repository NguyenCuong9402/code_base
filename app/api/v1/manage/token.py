
from flask import Blueprint
from app.models import TokenModel
from app.api.helper import send_error, send_result, Token
from app.extensions import jwt, db, logger
from app.utils import trim_dict, get_timestamp_now
from app.gateway import authorization_require

api = Blueprint('manage/token', __name__)


@api.route('/auto-remove-token', methods=['DELETE'])
@authorization_require()
def remove_token():
    try:
        TokenModel.query.filter(TokenModel.expires < get_timestamp_now()).delete()
        db.session.flush()
        db.session.commit()
        return send_result(message='Done')
    except Exception as ex:
        db.session.flush()
        return send_error(message=str(ex))