from sqlalchemy import create_engine, ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from datetime import datetime
from typing import List, Optional


class Base(DeclarativeBase):
    pass


class SDWANInstance(Base):
    __tablename__ = 'inventory'
    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String, nullable=False)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    sys_type: Mapped[Optional[str]] = mapped_column(String, default=None)  # vManage / vSmart
    version: Mapped[Optional[str]] = mapped_column(String, default=None)
    forensics_captured: Mapped[bool] = mapped_column(default=False)
    snapshot_captured: Mapped[bool] = mapped_column(default=False)
    core_dump_captured: Mapped[bool] = mapped_column(default=False)
    home_dir_copied: Mapped[bool] = mapped_column(default=False)
    patch_applied: Mapped[bool] = mapped_column(default=False)
    # ── Threat Hunt Checklist (per Supplemental Direction ED 26-03) ──
    hunt_completed: Mapped[bool] = mapped_column(default=False)
    hunt_omp_peers_checked: Mapped[bool] = mapped_column(default=False)
    hunt_control_connections_checked: Mapped[bool] = mapped_column(default=False)
    hunt_unauthorized_users_checked: Mapped[bool] = mapped_column(default=False)
    hunt_version_downgrade_checked: Mapped[bool] = mapped_column(default=False)
    hunt_audit_logs_checked: Mapped[bool] = mapped_column(default=False)
    hunt_config_changes_checked: Mapped[bool] = mapped_column(default=False)
    # ── Hardening ──
    hardening_implemented: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[Optional[str]] = mapped_column(String, default="")
    timestamp: Mapped[Optional[datetime]] = mapped_column(default_factory=datetime.utcnow)
    last_updated: Mapped[Optional[datetime]] = mapped_column(
        default_factory=datetime.utcnow, onupdate=datetime.utcnow
    )

    hunt_findings: Mapped[List["HuntFinding"]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class HuntFinding(Base):
    """Log individual threat hunt findings per asset for the March 5 report."""
    __tablename__ = 'hunt_findings'
    id: Mapped[int] = mapped_column(primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey('inventory.id'))
    category: Mapped[str] = mapped_column(String)  # e.g. "Rogue Peer", "Unauthorized User"
    severity: Mapped[str] = mapped_column(String, default="INFO")  # INFO / WARNING / CRITICAL
    description: Mapped[str] = mapped_column(Text)
    evidence: Mapped[Optional[str]] = mapped_column(Text, default="")  # CLI output / log excerpt
    analyst: Mapped[Optional[str]] = mapped_column(String, default="")
    timestamp: Mapped[Optional[datetime]] = mapped_column(default_factory=datetime.utcnow)

    asset: Mapped["SDWANInstance"] = relationship(back_populates="hunt_findings")


# Use SQLite for immediate "Clone & Run" capability
# For production, swap to: 'postgresql://user:pass@host/dbname'
engine = create_engine(
    'sqlite:///compliance_data.db',
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)
