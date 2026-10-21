from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from ..deps import AdminDep, CurrentUserDep, DBDep, require_admin
from ..models import Article, Item, Plan
from ..repository import ItemRepository

router = APIRouter()


@router.get("/items/{item_id}")
async def scoped_query(item_id: int, user: CurrentUserDep, db: DBDep):
    stmt = select(Item).where(Item.id == item_id, Item.owner_id == user.id)
    return (await db.execute(stmt)).scalar_one_or_none()


@router.get("/items/{item_id}/checked")
async def checked_after(item_id: int, user: CurrentUserDep, db: DBDep):
    item = await db.get(Item, item_id)
    if item is None or item.owner_id != user.id:
        raise HTTPException(404)
    return item


@router.get("/items/{item_id}/repo")
async def repository_scoped(item_id: int, user: CurrentUserDep, db: DBDep):
    return await ItemRepository(db).get_for_user(item_id, user_id=user.id)


@router.get("/items/{item_id}/bound-repo")
async def repository_bound_to_user(item_id: int, user: CurrentUserDep, db: DBDep):
    repo = ItemRepository(db, owner=user)
    return await repo.get(item_id)


@router.get("/admin/items/{item_id}")
async def admin_reads_anything(item_id: int, _admin: AdminDep, db: DBDep):
    return await db.get(Item, item_id)


admin = APIRouter(dependencies=[Depends(require_admin)])


@admin.delete("/admin/items/{item_id}")
async def admin_router(item_id: int, user: CurrentUserDep, db: DBDep):
    return await db.get(Item, item_id)


@router.get("/plans/{plan_id}")
async def public_plan(plan_id: int, user: CurrentUserDep, db: DBDep):
    return await db.get(Plan, plan_id)


@router.get("/users/{user_id}/items")
async def own_items_only(user_id: str, user: CurrentUserDep, db: DBDep):
    if user_id != str(user.id):
        raise HTTPException(404)
    return (await db.execute(select(Item).where(Item.owner_id == user_id))).scalars().all()


@router.get("/superuser/items/{item_id}")
async def gated_in_handler(item_id: int, user: CurrentUserDep, db: DBDep):
    if not user.is_superuser:
        raise HTTPException(403)
    return await db.get(Item, item_id)


@router.get("/template/items/{id}")
def full_stack_template_style(id: int, current_user: CurrentUserDep, session: DBDep):
    item = session.get(Item, id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    if not current_user.is_superuser and (item.owner_id != current_user.id):
        raise HTTPException(status_code=400, detail="Not enough permissions")
    return item


@router.get("/articles/{slug}")
async def published_article(slug: str, user: CurrentUserDep, db: DBDep):
    stmt = select(Article).where(Article.slug == slug, Article.published.is_(True))
    return (await db.execute(stmt)).scalar_one_or_none()


@router.get("/stepwise/{item_id}")
async def stepwise(item_id: int, user: CurrentUserDep, db: DBDep):
    stmt = select(Item).where(Item.id == item_id)
    stmt = stmt.where(Item.owner_id == user.id)
    return (await db.execute(stmt)).scalar_one_or_none()


@router.get("/public/items/{item_id}")
async def no_principal_at_all(item_id: int, db: DBDep):
    # Unauthenticated by design: whether that is right is not this rule's call.
    return await db.get(Item, item_id)


async def load_owned_item(item_id: int, user: CurrentUserDep, db: DBDep) -> Item:
    stmt = select(Item).where(Item.id == item_id, Item.owner_id == user.id)
    item = (await db.execute(stmt)).scalar_one_or_none()
    if item is None:
        raise HTTPException(404)
    return item


@router.put("/items/{item_id}/dep")
async def via_scoped_dependency(item: Item = Depends(load_owned_item)):
    return item


async def load_item(item_id: int, db: DBDep) -> Item:
    return await db.get(Item, item_id)


@router.put("/items/{item_id}/checked-dep")
async def dependency_checked_in_handler(user: CurrentUserDep, item: Item = Depends(load_item)):
    if item.owner_id != user.id:
        raise HTTPException(404)
    return item


@router.get("/items/{item_id}/suppressed")
async def suppressed(item_id: int, user: CurrentUserDep, db: DBDep):
    return await db.get(Item, item_id)  # fpg: ignore[FPG001] items here are shared by design (fixture)
