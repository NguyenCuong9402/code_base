from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from app.extensions import db
from sqlalchemy import distinct
from sqlalchemy.dialects.mysql import INTEGER
from app.utils import get_timestamp_now


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(100))
    type = db.Column(db.SmallInteger, default=1)  # 1: normal user, 2: admin, 3 super admin
    birthday = db.Column(db.DATE)
    address = db.Column(db.Text)  # Tỉnh, thành của user (FE tự convert)
    avatar_url = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, default=1)  # 1: Mở tài khoản , 0: Khóa tài khoản
    status = db.Column(db.Boolean, default=1)  # 1: Kích hoạt, 0: Không kích hoạt
    created_date = db.Column(INTEGER(unsigned=True), default=get_timestamp_now(), index=True)
    modified_date = db.Column(INTEGER(unsigned=True), default=0)
    created_user_id = db.Column(ForeignKey('user.id', ondelete='SET NULL', onupdate='CASCADE'), nullable=True)
    last_modified_user_id = db.Column(ForeignKey('user.id', ondelete='SET NULL', onupdate='CASCADE'), nullable=True)
    force_change_password = db.Column(db.Boolean, default=0)
    reset_password = db.Column(db.Boolean, default=0)
    modified_date_password = db.Column(INTEGER(unsigned=True), default=get_timestamp_now())


def get_permission_resource(user_id: str):
    query = UserGroupRole.query.filter(UserGroupRole.user_id == user_id)
    query_role = query.filter(UserGroupRole.group_id.is_(None)).all()
    list_role = [item.role_id for item in query_role]
    user_groups = query.filter(UserGroupRole.role_id.is_(None)).all()
    group_ids = [group.group_id for group in user_groups]
    group_role = UserGroupRole.query.filter(UserGroupRole.user_id.is_(None),
                                            UserGroupRole.group_id.in_(group_ids)) \
        .with_entities(UserGroupRole.role_id).all()
    list_role += [item.role_id for item in group_role if item.role_id not in list_role]
    resources = db.session.query(Permission.resource).join(RolePermission). \
        filter(RolePermission.role_id.in_(list_role)).all()
    list_permission = [resource[0] for resource in resources]
    return list_permission


def get_roles_key(user_id: str):
    query_role = UserGroupRole.query.filter(UserGroupRole.user_id == user_id, UserGroupRole.group_id.is_(None))\
        .with_entities(UserGroupRole.role_id).all()
    list_role = [item.role_id for item in query_role]
    group_ids = UserGroupRole.query.filter(UserGroupRole.user_id == user_id, UserGroupRole.role_id.is_(None))\
        .with_entities(UserGroupRole.group_id).subquery()
    group_role = UserGroupRole.query.filter(UserGroupRole.user_id.is_(None),
                                            UserGroupRole.group_id.in_(group_ids)) \
        .with_entities(UserGroupRole.role_id).all()
    list_role += [item.role_id for item in group_role if item.role_id not in list_role]
    keys = db.session.query(distinct(Role.key)).filter(Role.id.in_(list_role)).all()
    key_list = [key[0] for key in keys]
    return key_list


class Group(db.Model):
    __tablename__ = 'group'

    id = db.Column(db.String(50), primary_key=True)
    key = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.String(500))
    created_date = db.Column(INTEGER(unsigned=True), default=get_timestamp_now(), nullable=False, index=True)
    modified_date = db.Column(INTEGER(unsigned=True), default=0)
    last_modified_user = db.Column(ForeignKey('user.id', ondelete='SET NULL', onupdate='CASCADE'))
    created_user = db.Column(ForeignKey('user.id', ondelete='SET NULL', onupdate='CASCADE'))
    modified_user_data = relationship('User', foreign_keys="Group.last_modified_user")
    created_user_data = relationship('User', foreign_keys="Group.created_user")


class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    key = db.Column(db.String(100), nullable=False)
    type = db.Column(db.Integer, default=0)
    description = db.Column(db.String(500))
    created_date = db.Column(INTEGER(unsigned=True), default=get_timestamp_now())
    modified_date = db.Column(INTEGER(unsigned=True), default=0)
    last_modified_user = db.Column(ForeignKey('user.id', ondelete='SET NULL', onupdate='CASCADE'))
    created_user = db.Column(ForeignKey('user.id', ondelete='SET NULL', onupdate='CASCADE'))
    permissions = db.relationship("Permission", back_populates="roles", secondary="role_permission")
    modified_user_data = relationship('User', foreign_keys="Role.last_modified_user")
    created_user_data = relationship('User', foreign_keys="Role.created_user")


class Permission(db.Model):
    __tablename__ = 'permission'

    id = db.Column(db.String(50), primary_key=True)
    key = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100), nullable=False)
    roles = db.relationship("Role", back_populates="permissions", secondary="role_permission")


class RolePermission(db.Model):
    __tablename__ = 'role_permission'

    id = db.Column(db.String(50), primary_key=True)
    permission_id = db.Column(db.String(50), db.ForeignKey('permission.id', ondelete='CASCADE', onupdate='CASCADE'),
                              primary_key=True, nullable=False)
    role_id = db.Column(db.String(50), db.ForeignKey('role.id', ondelete='CASCADE', onupdate='CASCADE'),
                        primary_key=True, nullable=False)


class UserGroupRole(db.Model):
    __tablename__ = 'user_group_role'

    id = db.Column(db.String(50), primary_key=True)
    user_id = db.Column(db.String(50), db.ForeignKey('user.id', ondelete='CASCADE', onupdate='CASCADE'), nullable=True)
    group_id = db.Column(db.String(50), db.ForeignKey('group.id', ondelete='CASCADE', onupdate='CASCADE'),  nullable=True)
    role_id = db.Column(db.String(50), db.ForeignKey('role.id', ondelete='CASCADE', onupdate='CASCADE'),  nullable=True)


class TokenModel(db.Model):
    __tablename__ = 'token'
    id = db.Column(db.String(50), primary_key=True)
    user_id = db.Column(db.String(50), db.ForeignKey('user.id'), primary_key=True, nullable=False)
    jti = db.Column(db.String(200))
    encoded_token = db.Column(db.Text)
    expires = db.Column(db.Integer)


class Message(db.Model):
    __tablename__ = 'message'

    id = db.Column(db.String(50), primary_key=True)
    description = db.Column(db.String(255))
    show = db.Column(db.Boolean, default=0)
    duration = db.Column(db.Integer, default=5)
    status = db.Column(db.String(20), default='success')
    message = db.Column(db.String(500), nullable=False)
    dynamic = db.Column(db.Boolean, default=0)
    object = db.Column(db.String(255))