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

    def import_rbac(self):
        file_name = "import_phan_quyen.xlsx"
        # import permission
        df_permission = pd.read_excel(file_name, sheet_name='permission')
        list_add_permission = []
        for index, row in df_permission.iterrows():
            existing_permission = Permission.query.filter(Permission.key == row['key'],
                                                          Permission.name == row['name'],
                                                          Permission.resource == row['resource']).first()
            if existing_permission is None:
                existing_permission = Permission(
                    id=str(uuid.uuid4()),
                    key=row['key'],
                    name=row['name'],
                    resource=row['resource']
                )
                list_add_permission.append(existing_permission)
        db.session.bulk_save_objects(list_add_permission)
        db.session.commit()
        # import role
        df_role = pd.read_excel(file_name, sheet_name='role')
        for index, row in df_role.iterrows():
            existing_role = Role.query.filter(Role.key == row['key'], Role.name == row['name'],
                                              Role.type == row['type']).first()
            if existing_role is None:
                existing_role = Role(
                    id=str(uuid.uuid4()),
                    key=row['key'],
                    name=row['name'],
                    type=row['type'],
                    description=row['description']
                )
                db.session.add(existing_role)
                db.session.flush()
                list_method = convert_method_by_type(row['type'])

                permission_data = []
                for item in list_method:
                    result = Permission.query.filter(Permission.key == existing_role.key,
                                                     Permission.resource.ilike(f'%{item}%')).all()
                    permission_data.extend(result)
                list_add_role_permission = []
                for permission in permission_data:
                    role_permission = RolePermission(id=str(uuid.uuid1()), permission_id=permission.id,
                                                     role_id=existing_role.id)
                    list_add_role_permission.append(role_permission)
                db.session.bulk_save_objects(list_add_role_permission)
        db.session.commit()
        # import group
        df_group = pd.read_excel(file_name, sheet_name='group')
        for index, row in df_group.iterrows():
            existing_group = Group.query.filter(Group.key == row['key'], Group.name == row['name']).first()
            if existing_group is None:
                existing_group = Role(
                    id=str(uuid.uuid4()),
                    key=row['key'],
                    name=row['name'],
                    description=row['description']
                )
                db.session.add(existing_group)
                db.session.flush()
                try:
                    roles_id = json.loads(row['roles_id'])
                except:
                    roles_id = []
                roles = Role.query.filter(Role.key.in_(roles_id)).all()
                for role in roles:
                    group_role = UserGroupRole(id=str(uuid.uuid1()), role_id=role.id, group_id=existing_group.id)
                    db.session.add(group_role)
        db.session.commit()
        # import user
        df_user = pd.read_excel(file_name, sheet_name='user')
        for index, row in df_user.iterrows():
            existing_user = User.query.filter(User.email == row['email']).first()
            if existing_user is None:
                existing_user = User(
                    id=str(uuid.uuid4()),
                    full_name=row['full_name'],
                    password_hash=row['password_hash'],
                    email=row['email'],
                    type=row['type']
                )
                db.session.add(existing_user)
                db.session.flush()
                list_user_group_role = []
                try:
                    roles_key = json.loads(row['roles_key'])
                except:
                    roles_key = []
                roles = Role.query.filter(Role.key.in_(roles_key)).all()
                for role in roles:
                    user_role = UserGroupRole(id=str(uuid.uuid1()), role_id=role.id, user_id=existing_user.id)
                    list_user_group_role.append(user_role)
                try:
                    groups_key = json.loads(row['groups_key'])
                except:
                    groups_key = []

                groups = Group.query.filter(Group.key.in_(groups_key)).all()
                for group in groups:
                    user_group = UserGroupRole(id=str(uuid.uuid1()), group_id=group.id, user_id=existing_user.id)
                    list_user_group_role.append(user_group)
                db.session.bulk_save_objects(list_user_group_role)
        db.session.commit()


if __name__ == '__main__':
    print("=" * 10, f"Starting update rbac to the database on the uri: {CONFIG.SQLALCHEMY_DATABASE_URI}", "=" * 10)
    worker = Worker()
    worker.import_rbac()
    print("=" * 50, "update rbac", "=" * 50)