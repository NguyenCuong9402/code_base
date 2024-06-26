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

    # redis config
    REDIS_HOST = 'redis_base_stg'
    # REDIS_HOST = '127.0.0.1'
    REDIS_PORT = 6379
    REDIS_DB = 1
    REDIS_PASSWORD = 'cuong-boot-ai'

    # mysql config
    SQLALCHEMY_DATABASE_URI = 'mysql://root:G-^rqEyhE6p=A#u*RU:V9J6-@192.168.1.17:3306/demo_stg'
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    # email config
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = 'nguyenngoccuong.ubtlu@gmail.com'
    MAIL_PASSWORD = 'gufxxahiyzmzmxrr'
    MAIL_DEFAULT_SENDER = 'nguyenngoccuong.ubtlu@gmail.com'
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEBUG = False


class PrdConfig(Config):
    """Development configuration."""
    # app config
    ENV = 'prd'
    DEBUG = True
    DEBUG_TB_ENABLED = True  # Disable Debug toolbar
    TEMPLATES_AUTO_RELOAD = True
    HOST = '0.0.0.0'

    # version
    VERSION = "Prd_2.0"

    # JWT Config
    JWT_SECRET_KEY = '12345678a@'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # redis config
    REDIS_HOST = 'redis_base_stg'
    # REDIS_HOST = '127.0.0.1'
    REDIS_PORT = 6379
    REDIS_DB = 1
    REDIS_PASSWORD = 'cuong-boot-ai'

    # mysql config
    SQLALCHEMY_DATABASE_URI = 'mysql://root:G-^rqEyhE6p=A#u*RU:V9J6-@192.168.1.17:3306/demo_stg'
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    # email config
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = 'nguyenngoccuong.ubtlu@gmail.com'
    MAIL_PASSWORD = 'gufxxahiyzmzmxrr'
    MAIL_DEFAULT_SENDER = 'nguyenngoccuong.ubtlu@gmail.com'
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEBUG = False


class StgConfig(Config):
    """Development configuration."""
    # app config
    ENV = 'stg'
    DEBUG = True
    DEBUG_TB_ENABLED = True  # Disable Debug toolbar
    TEMPLATES_AUTO_RELOAD = True
    HOST = '0.0.0.0'

    # version
    VERSION = "Stg_3.0"

    # JWT Config
    JWT_SECRET_KEY = '12345678a@'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # redis config
    REDIS_HOST = 'redis_base_stg'
    # REDIS_HOST = '127.0.0.1'
    REDIS_PORT = 6379
    REDIS_DB = 1
    REDIS_PASSWORD = 'cuong-boot-ai'

    # mysql config
    SQLALCHEMY_DATABASE_URI = 'mysql://root:G-^rqEyhE6p=A#u*RU:V9J6-@192.168.1.17:3306/demo_stg'
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    # email config
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 465
    MAIL_USERNAME = 'nguyenngoccuong.ubtlu@gmail.com'
    MAIL_PASSWORD = 'gufxxahiyzmzmxrr'
    MAIL_DEFAULT_SENDER = 'nguyenngoccuong.ubtlu@gmail.com'
    MAIL_USE_TLS = False
    MAIL_USE_SSL = True
    MAIL_DEBUG = False


