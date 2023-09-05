"""empty message

Revision ID: 52b76e10c997
Revises: fef0a436fa61
Create Date: 2023-09-05 13:50:23.634132

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '52b76e10c997'
down_revision = 'fef0a436fa61'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('email_template',
    sa.Column('id', sa.String(length=50), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=True),
    sa.Column('body', sa.TEXT(), nullable=True),
    sa.Column('description', sa.String(length=200), nullable=True),
    sa.Column('template_code', sa.String(length=200), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('email_template')
    # ### end Alembic commands ###