from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from app.extensions import db
from sqlalchemy.ext.hybrid import hybrid_property


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(100))
    phone = db.Column(db.String(50))
    password_hash = db.Column(db.String(255))
    full_name = db.Column(db.String(100))
    type = db.Column(db.SmallInteger, default=1)  # 1: normal user, 2: admin, 3 super admin
    groups = db.relationship("Group", secondary="user_group_role", back_populates="users")
    roles = db.relationship("Role", secondary="user_group_role", back_populates="users")

    @hybrid_property
    def permission(self):
        return get_list_permission(self.id)


def get_list_permission(user_id):
    query = UserGroupRole.query.filter(UserGroupRole.user_id == user_id)
    query_role = query.filter(UserGroupRole.group_id.is_(None)).with_entities(UserGroupRole.role_id).all()
    list_role = [item.role_id for item in query_role]
    group_ids = query.filter(UserGroupRole.role_id.is_(None)).with_entities(UserGroupRole.group_id).subquery()
    group_role = UserGroupRole.query.filter(UserGroupRole.user_id.is_(None),
                                            UserGroupRole.group_id.in_(group_ids)) \
        .with_entities(UserGroupRole.role_id).all()
    list_role += [item.role_id for item in group_role if item.role_id not in list_role]
    resources = db.session.query(Permission.resource).join(RolePermission). \
        filter(RolePermission.role_id.in_(list_role)).all()
    list_permission = [resource[0] for resource in resources]
    return list_permission


class Group(db.Model):
    __tablename__ = 'group'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    roles = db.relationship("Role", secondary="user_group_role", back_populates="groups")
    users = db.relationship("User", secondary="user_group_role", back_populates="groups")


class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    key = db.Column(db.String(100), nullable=False)
    type = db.Column(db.Integer, default=0)
    permissions = db.relationship("Permission", back_populates="roles", secondary="role_permission")
    groups = db.relationship("Group", secondary="user_group_role", back_populates="roles")
    users = db.relationship("User", secondary="user_group_role", back_populates="roles")


class Permission(db.Model):
    __tablename__ = 'permission'

    id = db.Column(db.String(50), primary_key=True)
    key = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100), nullable=False, unique=True)
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
    user_id = db.Column(db.String(50), db.ForeignKey('user.id', ondelete='CASCADE', onupdate='CASCADE'),
                        primary_key=True)
    group_id = db.Column(db.String(50), db.ForeignKey('group.id', ondelete='CASCADE', onupdate='CASCADE'),
                         primary_key=True)
    role_id = db.Column(db.String(50), db.ForeignKey('role.id', ondelete='CASCADE', onupdate='CASCADE'),
                        primary_key=True)


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