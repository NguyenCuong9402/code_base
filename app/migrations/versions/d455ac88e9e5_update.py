"""update

Revision ID: d455ac88e9e5
Revises: e68e1f21a3b1
Create Date: 2023-08-18 14:54:06.871664

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'd455ac88e9e5'
down_revision = 'e68e1f21a3b1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user', sa.Column('modified_date', mysql.INTEGER(unsigned=True), nullable=True))
    op.add_column('user', sa.Column('modified_date_password', mysql.INTEGER(unsigned=True), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'modified_date_password')
    op.drop_column('user', 'modified_date')
    # ### end Alembic commands ###
