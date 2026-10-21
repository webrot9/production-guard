import asyncio

from fastapi import HTTPException
from sqlalchemy import select, text, update

from ..models import CreditTransaction, User, VersionedWallet, get_balance


async def guarded_update(db, user_id: int, cost: int):
    result = await db.execute(
        update(User).where(User.id == user_id, User.credits >= cost).values(credits=User.credits - cost)
    )
    if result.rowcount == 0:
        raise HTTPException(402)


async def locked_counter(session, user_id: int, cost: int):
    user = (await session.execute(select(User).where(User.id == user_id).with_for_update())).scalar_one()
    if user.credits < cost:
        raise HTTPException(402)
    user.credits -= cost
    await session.commit()


async def locked_ledger(session, user_id: int, cost: int):
    await session.execute(select(User.id).where(User.id == user_id).with_for_update())
    balance = await get_balance(session, user_id)
    if balance < cost:
        raise HTTPException(402)
    session.add(CreditTransaction(user_id=user_id, delta=-cost))


async def advisory_locked(session, user_id: int, cost: int):
    await session.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": user_id})
    balance = await get_balance(session, user_id)
    if balance >= cost:
        session.add(CreditTransaction(user_id=user_id, delta=-cost))


async def via_helper_lock(session, repo, user_id: int, cost: int):
    await repo.lock_user_row(user_id)
    balance = await get_balance(session, user_id)
    if balance < cost:
        raise HTTPException(402)
    session.add(CreditTransaction(user_id=user_id, delta=-cost))


async def refreshed_for_update(session, user: User, cost: int):
    await session.refresh(user, with_for_update=True)
    if user.credits < cost:
        raise HTTPException(402)
    user.credits -= cost


async def optimistic(session, wallet: VersionedWallet, cost: int):
    wallet.balance -= cost
    await session.commit()


async def grant_only(session, user_id: int, amount: int):
    # A grant that never reads the balance cannot overspend it.
    session.add(CreditTransaction(user_id=user_id, delta=amount))


def in_memory_only(cart, cost):
    # No session anywhere: an in-memory object, not a row.
    cart.credits -= cost
    return cart


async def show_balance(session, user_id: int):
    return {"balance": await get_balance(session, user_id)}
