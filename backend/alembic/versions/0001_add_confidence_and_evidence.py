"""Add confidence and evidence to findings

Revision ID: 0001_conf_ev
Revises: 
Create Date: 2026-10-28 08:35:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001_conf_ev'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('confidence', sa.String(length=20), server_default='likely', nullable=False)
        )
        batch_op.add_column(
            sa.Column('evidence', sa.Text(), nullable=True)
        )
        batch_op.create_index(
            batch_op.f('ix_findings_confidence'), ['confidence'], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_confidence'))
        batch_op.drop_column('evidence')
        batch_op.drop_column('confidence')

