from app.enums import MESSAGE_ID
from app.validator import UserSchema, UpdateProfileSchema
from flask import Blueprint, request
from flask_jwt_extended import get_jwt_identity
from app.models import User
from app.api.helper import send_error, send_result
from app.extensions import db, mail
from app.utils import trim_dict, convert_str_to_date_time
from app.gateway import authorization_require
from flask_mail import Message as MessageMail
import json

api = Blueprint('profile', __name__)


@api.route('/send_email', methods=['POST'])
@authorization_require()
def send_email():
    try:
        title = request.form.get('title', 'ADMIN SEND MAIL')
        mails = json.loads(request.form.get('mails', []))
        body = request.form.get('body', 'This is a test email sent from Flask and Send file')
        msg = MessageMail(title, recipients=mails)
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                .envelope {
                    background-color: #F2F2F2;
                    width: 300px;
                    height: 200px;
                    position: relative;
                    margin: 0 auto;
                    border-radius: 10px;
                    transform: rotate(-10deg);
                }

                .envelope:before {
                    content: "";
                    position: absolute;
                    width: 0;
                    height: 0;
                    border-left: 40px solid transparent;
                    border-right: 40px solid transparent;
                    border-bottom: 80px solid #8B4513;
                    top: -60px;
                    left: 30px;
                }
                .email-content {
                    padding: 20px;
                    font-family: Arial, sans-serif;
                    font-size: 16px;
                     color: red;
                     text-align: center;
                     vertical-align: middle;
                }
            </style>
        </head>
        <body>
            <div class="envelope">
                <div class="email-content">
                    <p>BODY</p>
                </div>
            </div>
        </body>
        </html>
        """
        html_content = html_content.replace("BODY", body)
        msg.html = html_content

        files = request.files.getlist('files')
        for file in files:
            if file:
                msg.attach(file.filename, 'application/pdf', file.read())

        mail.send(msg)
        return send_result(message='send email thành công')
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('', methods=['GET'])
@authorization_require()
def get_profile():
    try:
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()
        return send_result(data=UserSchema(only=['email', 'phone', 'full_name', 'address',
                                                 'birthday', 'avatar_url', 'created_date']).dump(user))
    except Exception as ex:
        return send_error(message=str(ex))


@api.route('', methods=['PUT'])
@authorization_require()
def change_profile():
    try:
        code_lang = request.args.get('code_lang', 'EN')
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()
        if user is None:
            return send_error(message='NOT_FOUND_ERROR', code_lang=code_lang, message_id=MESSAGE_ID)
        try:
            json_req = request.get_json()
        except Exception as ex:
            return send_error(message="Request Body incorrect json format: " + str(ex), code=442)
        # trim input body
        json_body = trim_dict(json_req)
        # validate request body
        validator_input = UpdateProfileSchema()
        is_not_validate = validator_input.validate(json_body)
        if is_not_validate:
            return send_error(data=is_not_validate, message='INVALID_PASSWORD', code_lang=code_lang,
                              message_id=MESSAGE_ID)
        json_req["birthday"] = convert_str_to_date_time(json_req["birthday"])
        for key in json_req.keys():
            user.__setattr__(key, json_req[key])
        db.session.flush()
        db.session.commit()
        return send_result(data=UserSchema(only=['email', 'phone', 'full_name', 'address', 'birthday', 'avatar_url',
                                                 'created_date']).dump(user), message='success')
    except Exception as ex:
        db.session.rollback()
        return send_error(message=str(ex))
