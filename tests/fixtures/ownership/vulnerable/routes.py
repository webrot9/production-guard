from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, select

from ..deps import CurrentUserDep, DBDep, get_current_user
from ..models import Item, Note
from ..repository import ItemRepository, fetch_item

router = APIRouter(prefix="/items")


@router.get("/{item_id}")
async def read_item(item_id: int, user: CurrentUserDep, db: DBDep):
    return await db.get(Item, item_id)  # V1


@router.patch("/{item_id}")
async def rename_item(item_id: int, title: str, user: CurrentUserDep, db: DBDep):
    item = (await db.execute(select(Item).where(Item.id == item_id))).scalar_one()  # V2
    item.title = title
    return item


@router.delete("/{item_id}")
async def delete_item(item_id: int, user: CurrentUserDep, db: DBDep):
    await db.execute(delete(Item).where(Item.id == item_id))  # V3


@router.get("/{item_id}/via-helper")
async def read_via_helper(item_id: int, user: CurrentUserDep, db: DBDep):
    return await fetch_item(db, item_id)  # V4


@router.get("/{item_id}/via-repo")
async def read_via_repo(item_id: int, user: CurrentUserDep, db: DBDep):
    repo = ItemRepository(db)
    return await repo.get(item_id)  # V5


@router.get("/{item_id}/checked-too-late")
async def checked_wrong_thing(item_id: int, user: CurrentUserDep, db: DBDep):
    item = await db.get(Item, item_id)  # V6
    if item is None:
        raise HTTPException(404)
    return item


def sync_read(note_id: int, db=Depends(lambda: None), current_user=Depends(get_current_user)):
    return db.query(Note).filter(Note.id == note_id).first()


router.add_api_route("/notes/{note_id}", sync_read, methods=["GET"])  # V7 is in sync_read


async def load_item(item_id: int, db: DBDep) -> Item:
    item = await db.get(Item, item_id)  # V8 (dependency)
    if item is None:
        raise HTTPException(404)
    return item


@router.put("/{item_id}/via-dependency")
async def update_via_dependency(user: CurrentUserDep, item: Item = Depends(load_item)):
    return item


authed = APIRouter(dependencies=[Depends(get_current_user)])


@authed.get("/anonymous-owner/{item_id}")
async def no_user_variable(item_id: int, db: DBDep):
    return await db.get(Item, item_id)  # V9


@router.get("/by-owner/{user_id}")
async def list_for_someone_else(user_id: str, user: CurrentUserDep, db: DBDep):
    return (await db.execute(select(Item).where(Item.owner_id == user_id))).scalars().all()  # V10
