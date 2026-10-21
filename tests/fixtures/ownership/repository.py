from sqlalchemy import select

from .models import Item


class ItemRepository:
    def __init__(self, session, owner=None):
        self.session = session
        self.owner = owner

    async def get(self, item_id):
        return await self.session.get(Item, item_id)

    async def get_for_user(self, item_id, *, user_id):
        stmt = select(Item).where(Item.id == item_id, Item.owner_id == user_id)
        return (await self.session.execute(stmt)).scalar_one_or_none()


async def fetch_item(db, item_id):
    result = await db.execute(select(Item).where(Item.id == item_id))
    return result.scalar_one_or_none()
