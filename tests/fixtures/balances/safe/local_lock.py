import asyncio

from ..models import User

_lock = asyncio.Lock()


async def process_local_lock(session, user: User, cost: int):
    # Looks serialised; is not, once there are two workers.
    async with _lock:
        if user.credits >= cost:
            user.credits -= cost  # still a finding: V7
            await session.commit()
