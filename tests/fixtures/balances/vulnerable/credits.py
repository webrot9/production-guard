from fastapi import HTTPException
from sqlalchemy import update

from ..models import CreditTransaction, User, get_balance


async def spend_counter(session, user: User, cost: int):
    if user.credits < cost:
        raise HTTPException(402)
    user.credits -= cost  # V1
    await session.commit()


async def spend_assign(session, user_id: int, cost: int):
    user = await session.get(User, user_id)
    remaining = user.credits - cost
    if remaining < 0:
        raise HTTPException(402)
    user.credits = remaining  # V2
    await session.commit()


async def spend_ledger(session, user_id: int, cost: int):
    balance = await get_balance(session, user_id)
    if balance < cost:
        raise HTTPException(402)
    session.add(CreditTransaction(user_id=user_id, delta=-cost))  # V3
    await session.commit()


async def expire_down_to(session, user_id: int, amount: int):
    balance = await get_balance(session, user_id)
    burn = min(amount, balance)
    row = CreditTransaction(user_id=user_id, delta=-burn)  # V4
    session.add(row)
    await session.flush()


async def stale_check_atomic_update(db, user: User, cost: int):
    if user.credits < cost:
        raise HTTPException(402)
    await db.execute(update(User).where(User.id == user.id).values(credits=User.credits - cost))  # V5


async def stale_value_to_writer(db, user_id: int, allowance: int):
    excess = await get_balance(db, user_id) - allowance
    if excess > 0:
        await expire_down_to(db, user_id, excess)  # V6 (medium)
