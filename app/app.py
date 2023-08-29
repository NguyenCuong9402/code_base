import json

from .api import v1 as api_v1
from flask import Flask
from flask_cors import CORS
from .models import Message
from .api.helper import send_result, send_error
from .extensions import jwt, db, migrate, CONFIG, red
from .redis_manage import add_messages_to_redis


def create_app(config_object=CONFIG):
    """
    Init App
    :param config_object:
    :return:
    """
    app = Flask(__name__, static_url_path="/files", static_folder="./files")
    app.config.from_object(config_object)
    register_extensions(app)
    register_monitor(app)
    register_blueprints(app)
    CORS(app, expose_headers=["Content-Disposition"])
    add_messages_to_redis()

    # pubsub = red.pubsub()
    #
    # @db.event.listens_for(Message, 'after_insert')
    # @db.event.listens_for(Message, 'after_update')
    # def receive_after_insert_update(mapper, connection, target):
    #     # Chuyển đối tượng Message thành chuỗi JSON
    #     message_json = json.dumps({
    #         "id": target.id,
    #         "message_id": target.message_id,
    #         "description": target.description,
    #         "show": target.show,
    #         "duration": target.duration,
    #         "status": target.status,
    #         "message": target.message,
    #         "dynamic": target.dynamic,
    #         "object": target.object,
    #         "code_lang": target.code_lang
    #     })
    #
    #     # Lưu chuỗi JSON vào Redis với key là message_id và code_lang
    #     key = f"message:{target.message_id}-{target.code_lang}"
    #     red.set(key, message_json)
    #
    #     # Gửi thông điệp tới kênh để cập nhật realtime
    #     pubsub.publish('message_update', key)
    #
    #
    # @db.event.listens_for(Message, 'after_delete')
    # def receive_after_delete(mapper, connection, target):
    #     # Xóa key tương ứng trong Redis
    #     key = f"message:{target.message_id}-{target.code_lang}"
    #     red.delete(key)
    #
    #     # Gửi thông điệp tới kênh để cập nhật realtime
    #     pubsub.publish('message_delete', key)

    return app


def register_extensions(app):
    """
    Init extension
    :param app:
    :return:
    """

    db.app = app
    db.init_app(app)  # SQLAlchemy
    jwt.init_app(app)
    migrate.init_app(app, db)
    red.init_app(app)


def register_monitor(app):
    def has_no_empty_params(rule):
        defaults = rule.defaults if rule.defaults is not None else ()
        arguments = rule.arguments if rule.arguments is not None else ()
        return len(defaults) >= len(arguments)

    @app.route("/api/v1/helper/site-map", methods=['GET'])
    def site_map():
        links = []
        for rule in app.url_map.iter_rules():
            # Filter out rules we can't navigate to in a browser
            # and rules that require parameters
            # if has_no_empty_params(rule):

            # url = url_for(rule.endpoint, **(rule.defaults or {}))
            request_method = ""
            if "GET" in rule.methods:
                request_method = "get"
            if "PUT" in rule.methods:
                request_method = "put"
            if "POST" in rule.methods:
                request_method = "post"
            if "DELETE" in rule.methods:
                request_method = "delete"
            permission_route = "{0}@{1}".format(request_method.lower(), rule)
            links.append(permission_route)
        return send_result(data=sorted(links, key=lambda resource: str(resource).split('@')[-1]))


def register_blueprints(app):
    """
    Init blueprint for api url
    :param app:
    :return:
    """
    # Management
    app.register_blueprint(api_v1.manage.user.api, url_prefix='/api/v1/manage/user')
    app.register_blueprint(api_v1.manage.import_file.api, url_prefix='/api/v1/manage/import_file')
    app.register_blueprint(api_v1.manage.group.api, url_prefix='/api/v1/manage/group')
    app.register_blueprint(api_v1.manage.role.api, url_prefix='/api/v1/manage/role')

    app.register_blueprint(api_v1.auth.api, url_prefix='/api/v1/auth')
    app.register_blueprint(api_v1.profile.api, url_prefix='/api/v1/profile')
