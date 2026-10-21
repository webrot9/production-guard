from sqlalchemy import ForeignKey, func, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    credits: Mapped[int] = mapped_column(default=0)


class VersionedWallet(Base):
    __tablename__ = "wallets"
    id: Mapped[int] = mapped_column(primary_key=True)
    balance: Mapped[int]
    version: Mapped[int]
    __mapper_args__ = {"version_id_col": version}


class CreditTransaction(Base):
    __tablename__ = "credit_transactions"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    delta: Mapped[int]


async def get_balance(session, user_id) -> int:
    stmt = select(func.coalesce(func.sum(CreditTransaction.delta), 0)).where(CreditTransaction.user_id == user_id)
    return (await session.execute(stmt)).scalar_one()
