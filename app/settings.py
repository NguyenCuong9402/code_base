import os

os_env = os.environ


class Config(object):
    SECRET_KEY = '3nF3Rn0sdf'
    APP_DIR = os.path.abspath(os.path.dirname(__file__))  # This directory
    PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, os.pardir))


class DevConfig(Config):
    """Development configuration."""
    # app config
    ENV = 'dev'
    DEBUG = True
    DEBUG_TB_ENABLED = True  # Disable Debug toolbar
    TEMPLATES_AUTO_RELOAD = True
    HOST = '0.0.0.0'

    # version
    VERSION = "1.0"

    # JWT Config
    JWT_SECRET_KEY = '12345678a@'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # mysql config
    SQLALCHEMY_DATABASE_URI = 'mysql://root:G-^rqEyhE6p=A#u*RU:V9J6-@sv4.vn.boot.ai:3306/demo_stg'
    SQLALCHEMY_TRACK_MODIFICATIONS = True





