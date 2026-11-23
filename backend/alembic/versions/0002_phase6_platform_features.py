"""Phase 6 Platform Features: Schedules, Report Shares, Api Keys, White Label, Finding Workflow

Revision ID: 0002_platform_feat
Revises: 0001_conf_ev
Create Date: 2026-10-29 16:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

revision = '0002_platform_feat'
down_revision = '0001_conf_ev'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 1. Alter findings table
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('status', sa.String(length=20), server_default='open', nullable=False)
        )
        batch_op.add_column(
            sa.Column('status_reason', sa.Text(), nullable=True)
        )
        batch_op.add_column(
            sa.Column('status_updated_at', sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column('status_updated_by', sa.String(length=36), nullable=True)
        )
        batch_op.create_index(
            batch_op.f('ix_findings_status'), ['status'], unique=False
        )

    # 2. finding_audit_logs
    op.create_table(
        'finding_audit_logs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('old_status', sa.String(length=20), nullable=False),
        sa.Column('new_status', sa.String(length=20), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_finding_audit_logs_finding_id'), 'finding_audit_logs', ['finding_id'], unique=False)
    op.create_index(op.f('ix_finding_audit_logs_user_id'), 'finding_audit_logs', ['user_id'], unique=False)

    # 3. schedules
    op.create_table(
        'schedules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('profile', sa.String(length=20), nullable=False),
        sa.Column('frequency', sa.String(length=20), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('email_alert', sa.Boolean(), nullable=False),
        sa.Column('notification_email', sa.String(length=255), nullable=True),
        sa.Column('slack_webhook_url', sa.String(length=1024), nullable=True),
        sa.Column('generic_webhook_url', sa.String(length=1024), nullable=True),
        sa.Column('notify_on', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_schedules_domain'), 'schedules', ['domain'], unique=False)
    op.create_index(op.f('ix_schedules_user_id'), 'schedules', ['user_id'], unique=False)

    # 4. report_shares
    op.create_table(
        'report_shares',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('token', sa.String(length=64), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_revoked', sa.Boolean(), nullable=False),
        sa.Column('views_count', sa.Integer(), nullable=False),
        sa.Column('last_viewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_report_shares_token'), 'report_shares', ['token'], unique=True)
    op.create_index(op.f('ix_report_shares_scan_id'), 'report_shares', ['scan_id'], unique=False)

    # 5. api_keys
    op.create_table(
        'api_keys',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('key_prefix', sa.String(length=16), nullable=False),
        sa.Column('scopes', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_api_keys_key_hash'), 'api_keys', ['key_hash'], unique=True)
    op.create_index(op.f('ix_api_keys_user_id'), 'api_keys', ['user_id'], unique=False)

    # 6. white_label_configs
    op.create_table(
        'white_label_configs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('company_name', sa.String(length=255), nullable=False),
        sa.Column('logo_url', sa.String(length=1024), nullable=True),
        sa.Column('accent_color', sa.String(length=20), nullable=False),
        sa.Column('footer_text', sa.String(length=500), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_white_label_configs_user_id'), 'white_label_configs', ['user_id'], unique=True)


def downgrade() -> None:
    op.drop_table('white_label_configs')
    op.drop_table('api_keys')
    op.drop_table('report_shares')
    op.drop_table('schedules')
    op.drop_table('finding_audit_logs')
    with op.batch_alter_table('findings', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_findings_status'))
        batch_op.drop_column('status_updated_by')
        batch_op.drop_column('status_updated_at')
        batch_op.drop_column('status_reason')
        batch_op.drop_column('status')

