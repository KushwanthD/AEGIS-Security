from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, Float, func
from sqlalchemy.orm import relationship
from .connection import Base
from flask_login import UserMixin

class User(Base, UserMixin):
    __tablename__ = "Users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="Owner") # Admin, Analyst, Owner
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, server_default=func.now())

    assets = relationship("Asset", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")

class Asset(Base):
    __tablename__ = "Assets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("Users.id"), nullable=False)
    asset_type = Column(String, nullable=False) # domain, website
    asset_value = Column(String, unique=True, nullable=False)
    verification_status = Column(String, nullable=False, default="PENDING") # PENDING, TOKEN_GENERATED, VERIFIED, FAILED
    verification_token_hash = Column(String, nullable=True)
    verification_method = Column(String, nullable=True) # DNS, FILE
    verification_date = Column(DateTime, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    ssh_credentials = Column(Text, nullable=True) # JSON configuration for SSH host audits
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="assets")
    assessments = relationship("Assessment", back_populates="asset")
    audit_logs = relationship("AuditLog", back_populates="asset")

class Assessment(Base):
    __tablename__ = "Assessments"

    id = Column(Integer, primary_key=True, autoincrement=True)
    asset_id = Column(Integer, ForeignKey("Assets.id"), nullable=False)
    assessment_reference = Column(String, unique=True, nullable=False)
    status = Column(String, nullable=False, default="PENDING") # PENDING, APPROVED, REJECTED, COMPLETED, FAILED
    requested_at = Column(DateTime, server_default=func.now())
    approved_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Governance & Scope parameters
    scope_status = Column(String, nullable=False, default="IN_SCOPE") # IN_SCOPE, OUT_OF_SCOPE, EXPIRED
    allowed_targets = Column(String, nullable=True) # comma separated targets
    scope_expiry = Column(DateTime, nullable=True)
    scan_limit = Column(Integer, nullable=False, default=10)
    scan_usage = Column(Integer, nullable=False, default=0)

    asset = relationship("Asset", back_populates="assessments")
    approvals = relationship("Approval", back_populates="assessment")
    auth_tokens = relationship("AuthorizationToken", back_populates="assessment")
    recon_executions = relationship("ReconExecution", back_populates="assessment")
    scan_executions = relationship("ScanExecution", back_populates="assessment")
    correlation_executions = relationship("CorrelationExecution", back_populates="assessment")
    correlated_findings = relationship("CorrelatedFinding", back_populates="assessment")
    audit_logs = relationship("AuditLog", back_populates="assessment")
    reports = relationship("Report", back_populates="assessment")

class Approval(Base):
    __tablename__ = "Approvals"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    requested_by = Column(String, nullable=False)
    approved_by = Column(String, nullable=False)
    decision = Column(String, nullable=False) # APPROVED, REJECTED
    comments = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    assessment = relationship("Assessment", back_populates="approvals")

class AuthorizationToken(Base):
    __tablename__ = "AuthorizationTokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    token_hash = Column(String, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    expires_at = Column(DateTime, nullable=True)
    used = Column(Boolean, nullable=False, default=False)
    used_at = Column(DateTime, nullable=True)

    assessment = relationship("Assessment", back_populates="auth_tokens")

class ReconExecution(Base):
    __tablename__ = "ReconExecutions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, nullable=False) # RUNNING, COMPLETED, FAILED

    assessment = relationship("Assessment", back_populates="recon_executions")
    recon_results = relationship("ReconResult", back_populates="recon_execution")

class ReconResult(Base):
    __tablename__ = "ReconResults"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    recon_execution_id = Column(Integer, ForeignKey("ReconExecutions.id"), nullable=True)
    recon_type = Column(String, nullable=False) # DNS_A_RECORDS, DNS_MX_RECORDS, DNS_TXT_RECORDS, DNS_DMARC_RECORD
    result_data = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())

    recon_execution = relationship("ReconExecution", back_populates="recon_results")

class ScanExecution(Base):
    __tablename__ = "ScanExecutions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, nullable=False) # RUNNING, COMPLETED, FAILED

    assessment = relationship("Assessment", back_populates="scan_executions")
    scan_results = relationship("ScanResult", back_populates="scan_execution")

class ScanResult(Base):
    __tablename__ = "ScanResults"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    scan_execution_id = Column(Integer, ForeignKey("ScanExecutions.id"), nullable=True)
    tool_name = Column(String, nullable=False) # Nmap, Pixel Auditor
    finding_title = Column(String, nullable=False)
    finding_category = Column(String, nullable=True)
    severity = Column(String, nullable=True) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True) # JSON encoded data for pixel audit
    epss_score = Column(Float, nullable=True) # FIRST.org EPSS exploit probability
    epss_percentile = Column(Float, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    scan_execution = relationship("ScanExecution", back_populates="scan_results")

class CorrelationExecution(Base):
    __tablename__ = "CorrelationExecutions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    started_at = Column(DateTime, server_default=func.now())
    completed_at = Column(DateTime, nullable=True)
    status = Column(String, nullable=False) # RUNNING, COMPLETED, FAILED

    assessment = relationship("Assessment", back_populates="correlation_executions")
    correlated_findings = relationship("CorrelatedFinding", back_populates="correlation_execution")

class CorrelatedFinding(Base):
    __tablename__ = "CorrelatedFindings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    correlation_execution_id = Column(Integer, ForeignKey("CorrelationExecutions.id"), nullable=True)
    correlation_title = Column(String, nullable=False)
    risk_level = Column(String, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    correlation_reason = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    assessment = relationship("Assessment", back_populates="correlated_findings")
    correlation_execution = relationship("CorrelationExecution", back_populates="correlated_findings")

class ThreatIntel(Base):
    __tablename__ = "ThreatIntel"

    id = Column(Integer, primary_key=True, autoincrement=True)
    technology = Column(String, nullable=False)
    risk_level = Column(String, nullable=False)
    threat_title = Column(String, nullable=False)
    threat_description = Column(Text, nullable=False)
    recommended_action = Column(Text, nullable=False)
    source = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class Report(Base):
    __tablename__ = "Reports"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    report_type = Column(String, nullable=False) # TECHNICAL, EXECUTIVE
    file_name = Column(String, nullable=False)
    pdf_data = Column("pdf_data", type_=__import__('sqlalchemy').LargeBinary, nullable=True)  # PDF bytes stored in DB
    created_at = Column(DateTime, server_default=func.now())

    assessment = relationship("Assessment", back_populates="reports")

class AuditLog(Base):
    __tablename__ = "AuditLogs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("Users.id"), nullable=True)
    asset_id = Column(Integer, ForeignKey("Assets.id"), nullable=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=True)
    event_type = Column(String, nullable=False)
    event_details = Column(Text, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    user = relationship("User", back_populates="audit_logs")
    asset = relationship("Asset", back_populates="audit_logs")
    assessment = relationship("Assessment", back_populates="audit_logs")

class Notification(Base):
    __tablename__ = "Notifications"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("Users.id"), nullable=False)
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    read = Column(Boolean, nullable=False, default=False)
    link = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

class NetworkEdge(Base):
    __tablename__ = "NetworkEdges"

    id = Column(Integer, primary_key=True, autoincrement=True)
    assessment_id = Column(Integer, ForeignKey("Assessments.id"), nullable=False)
    source = Column(String, nullable=False) # e.g. "Internet", "Web Server"
    target = Column(String, nullable=False) # e.g. "Web Server", "Database Server"
    port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True) # e.g. "HTTPS", "SSH"
    risk_weight = Column(Float, default=1.0)
    created_at = Column(DateTime, server_default=func.now())

    assessment = relationship("Assessment", back_populates="network_edges")

# Add relation inside Assessment class
Assessment.network_edges = relationship("NetworkEdge", back_populates="assessment", cascade="all, delete-orphan")

