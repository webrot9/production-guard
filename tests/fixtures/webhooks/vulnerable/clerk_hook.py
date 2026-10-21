from fastapi import APIRouter, Header, Request

from ..models import SeenDelivery

router = APIRouter()


@router.post("/hooks/clerk")
async def clerk(request: Request, svix_id: str = Header(alias="svix-id")):
    db = request.state.db
    if await db.get(SeenDelivery, svix_id):
        return {"duplicate": True}
    db.add(SeenDelivery(delivery_id=svix_id))
    await send_welcome_email(await request.json())
    await db.commit()


async def send_welcome_email(payload): ...
