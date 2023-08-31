import json
import redis
from .api import v1 as api_v1
from flask import Flask, render_template
from flask_cors import CORS
from .models import Message
from .api.helper import send_result, send_error
from .extensions import jwt, db, migrate, CONFIG, red, mail, socketio
from .pubsub_manager import PubSubManager
from flask_socketio import emit

pubsub_manager = PubSubManager()


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

    @app.before_first_request
    def setup_redis():
        add_messages_to_redis()

    @app.route('/')
    def index():
        return render_template('index.html')

    @socketio.on('connect')
    def handle_connect():
        print('Client connected')

    @socketio.on('disconnect')
    def handle_disconnect():
        print('Client disconnected')
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
    mail.init_app(app)
    socketio.init_app(app)


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
    app.register_blueprint(api_v1.manage.message.api, url_prefix='/api/v1/manage/message')

    app.register_blueprint(api_v1.auth.api, url_prefix='/api/v1/auth')
    app.register_blueprint(api_v1.profile.api, url_prefix='/api/v1/profile')


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
