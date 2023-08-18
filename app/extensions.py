import os
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from .settings import ProdConfig, StgConfig, DevConfig

CONFIG = ProdConfig if os.environ.get('ENV') == 'prd' else StgConfig if os.environ.get('ENV') == 'stg' else DevConfig

jwt = JWTManager()

# init SQLAlchemy
db = SQLAlchemy()
migrate = Migrate()
