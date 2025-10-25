"""Initial schema

Revision ID: 001_initial
Revises:
Create Date: 2025-10-23

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001_initial'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create initial database schema."""

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), nullable=False, comment='Unique scan identifier (UUID)'),
        sa.Column('filename', sa.String(length=255), nullable=False, comment='Name of the scanned Terraform file'),
        sa.Column('file_hash', sa.String(length=64), nullable=False, comment='SHA-256 hash of file content'),
        sa.Column('file_size_bytes', sa.Integer(), nullable=False, comment='File size in bytes'),
        sa.Column('score', sa.Integer(), nullable=False, comment='Overall security score (0-100, higher = more risky)'),
        sa.Column('rule_based_score', sa.Integer(), nullable=False, comment='Score from rule-based analysis'),
        sa.Column('ml_score', sa.Float(), nullable=False, comment='Score from ML model'),
        sa.Column('confidence', sa.String(length=20), nullable=False, comment='Confidence level: LOW, MEDIUM, HIGH'),
        sa.Column('scan_duration_seconds', sa.Float(), nullable=False, comment='Time taken to scan in seconds'),
        sa.Column('from_cache', sa.Boolean(), nullable=False, server_default='false', comment='Whether result was from cache'),
        sa.Column('features_analyzed', sa.JSON(), nullable=False, server_default='{}', comment='Feature vector used by ML model'),
        sa.Column('vulnerability_summary', sa.JSON(), nullable=False, server_default='{}', comment='Summary of vulnerabilities by severity'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='When the scan was performed'),
        sa.Column('user_id', sa.String(length=255), nullable=True, comment='User or API key identifier who requested the scan'),
        sa.Column('correlation_id', sa.String(length=36), nullable=True, comment='Request correlation ID for tracing'),
        sa.Column('environment', sa.String(length=50), nullable=True, comment='Environment where scan was performed (dev, staging, prod)'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for scans table
    op.create_index('idx_scan_created_at', 'scans', ['created_at'])
    op.create_index('idx_scan_file_hash', 'scans', ['file_hash'])
    op.create_index('idx_scan_user_id', 'scans', ['user_id'])
    op.create_index('idx_scan_score', 'scans', ['score'])

    # Create vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Unique vulnerability identifier'),
        sa.Column('scan_id', sa.String(length=36), nullable=False, comment='ID of the scan that detected this vulnerability'),
        sa.Column('severity', sa.String(length=20), nullable=False, comment='Severity: CRITICAL, HIGH, MEDIUM, LOW, INFO'),
        sa.Column('points', sa.Integer(), nullable=False, comment='Risk points assigned to this vulnerability'),
        sa.Column('message', sa.Text(), nullable=False, comment='Description of the vulnerability'),
        sa.Column('resource', sa.String(length=255), nullable=False, comment='Terraform resource where vulnerability was found'),
        sa.Column('remediation', sa.Text(), nullable=False, comment='Recommended remediation steps'),
        sa.Column('category', sa.String(length=100), nullable=True, comment='Category: hardcoded_secret, open_port, public_access, etc.'),
        sa.Column('rule_id', sa.String(length=100), nullable=True, comment='ID of the security rule that detected this'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='When the vulnerability was detected'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for vulnerabilities table
    op.create_index('idx_vuln_scan_id', 'vulnerabilities', ['scan_id'])
    op.create_index('idx_vuln_severity', 'vulnerabilities', ['severity'])
    op.create_index('idx_vuln_category', 'vulnerabilities', ['category'])

    # Create scan_history table
    op.create_table(
        'scan_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Unique history entry identifier'),
        sa.Column('scan_id', sa.String(length=36), nullable=True, comment='ID of the related scan'),
        sa.Column('date', sa.DateTime(), nullable=False, comment='Date of the history entry'),
        sa.Column('total_scans', sa.Integer(), nullable=False, server_default='0', comment='Total number of scans performed'),
        sa.Column('average_score', sa.Float(), nullable=True, comment='Average security score'),
        sa.Column('critical_vulnerabilities', sa.Integer(), nullable=False, server_default='0', comment='Number of critical vulnerabilities found'),
        sa.Column('high_vulnerabilities', sa.Integer(), nullable=False, server_default='0', comment='Number of high severity vulnerabilities'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='When this history entry was created'),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for scan_history table
    op.create_index('idx_history_date', 'scan_history', ['date'])
    op.create_index('idx_history_scan_id', 'scan_history', ['scan_id'])

    # Create ml_model_versions table
    op.create_table(
        'ml_model_versions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False, comment='Unique model version identifier'),
        sa.Column('version', sa.String(length=50), nullable=False, comment='Model version (e.g., 1.0.0, 1.1.0)'),
        sa.Column('model_type', sa.String(length=100), nullable=False, comment='Type of model (e.g., IsolationForest)'),
        sa.Column('file_path', sa.String(length=500), nullable=False, comment='Path to the model file'),
        sa.Column('accuracy', sa.Float(), nullable=True, comment='Model accuracy score'),
        sa.Column('precision', sa.Float(), nullable=True, comment='Model precision score'),
        sa.Column('recall', sa.Float(), nullable=True, comment='Model recall score'),
        sa.Column('f1_score', sa.Float(), nullable=True, comment='Model F1 score'),
        sa.Column('training_samples', sa.Integer(), nullable=True, comment='Number of samples used for training'),
        sa.Column('training_date', sa.DateTime(), nullable=True, comment='When the model was trained'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='false', comment='Whether this version is currently active'),
        sa.Column('deployed_at', sa.DateTime(), nullable=True, comment='When this version was deployed'),
        sa.Column('metadata', sa.JSON(), nullable=True, comment='Additional model metadata'),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('CURRENT_TIMESTAMP'), comment='When this version was created'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('version')
    )

    # Create indexes for ml_model_versions table
    op.create_index('idx_model_version', 'ml_model_versions', ['version'])
    op.create_index('idx_model_is_active', 'ml_model_versions', ['is_active'])


def downgrade() -> None:
    """Drop all tables."""
    op.drop_table('ml_model_versions')
    op.drop_table('scan_history')
    op.drop_table('vulnerabilities')
    op.drop_table('scans')
