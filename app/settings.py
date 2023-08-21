import os

os_env = os.environ


class Config(object):
    SECRET_KEY = '3nF3Rn0sdf'
    APP_DIR = os.path.abspath(os.path.dirname(__file__))  # This directory
    PROJECT_ROOT = os.path.abspath(os.path.join(APP_DIR, os.pardir))


class ProdConfig(Config):
    """Production configuration."""
    ENV = 'prd'
    DEBUG = False
    DEBUG_TB_ENABLED = False
    HOST = '0.0.0.0'
    TEMPLATES_AUTO_RELOAD = False

    # version
    VERSION = "1.0"

    # JWT Config
    JWT_SECRET_KEY = '12345678a@'
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']

    # mysql config
    SQLALCHEMY_DATABASE_URI = 'mysql://root:XY58JqcxNLmy8SHN@192.168.1.212:3307/demo_stg'
    TIME_ZONE = 'Asia/Ho_Chi_Minh'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    BK_HOST_MYSQL = '192.168.1.17'
    BK_PORT_MYSQL = '3306'
    BK_USERNAME_MYSQL = 'root'
    BK_PASSWORD_MYSQL = 'G-^rqEyhE6p=A#u*RU:V9J6-'
    BK_DBNAME_MYSQL = 'demo_stg'


class StgConfig(Config):
    """Staging configuration."""
    # app config
    ENV = 'stg'
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
    SQLALCHEMY_DATABASE_URI = 'mysql://root:G-^rqEyhE6p=A#u*RU:V9J6-@192.168.1.17:3306/demo_stg'
    TIME_ZONE = 'Asia/Ho_Chi_Minh'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    BK_HOST_MYSQL = '192.168.1.17'
    BK_PORT_MYSQL = '3306'
    BK_USERNAME_MYSQL = 'root'
    BK_PASSWORD_MYSQL = 'G-^rqEyhE6p=A#u*RU:V9J6-'
    BK_DBNAME_MYSQL = 'demo_stg'


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
    TIME_ZONE = 'Asia/Ho_Chi_Minh'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    BK_HOST_MYSQL = '192.168.1.17'
    BK_PORT_MYSQL = '3306'
    BK_USERNAME_MYSQL = 'root'
    BK_PASSWORD_MYSQL = 'G-^rqEyhE6p=A#u*RU:V9J6-'
    BK_DBNAME_MYSQL = 'demo_stg'




