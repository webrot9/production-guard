from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class ProcessedEvent(Base):
    __tablename__ = "processed_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    provider: Mapped[str] = mapped_column(String(16))
    event_id: Mapped[str] = mapped_column(String(128))
    __table_args__ = (UniqueConstraint("provider", "event_id"),)


class SeenDelivery(Base):
    """No unique constraint: a check against this table is a race."""

    __tablename__ = "seen_deliveries"
    id: Mapped[int] = mapped_column(primary_key=True)
    delivery_id: Mapped[str] = mapped_column(String(128))


class CreditGrant(Base):
    __tablename__ = "credit_grants"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[str] = mapped_column(String(64))
    amount: Mapped[int]
