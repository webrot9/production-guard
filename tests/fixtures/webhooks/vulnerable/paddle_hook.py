from fastapi import APIRouter, Request

from .tasks import process_paddle_event

router = APIRouter()


@router.post("/paddle/webhook")
async def paddle(request: Request):
    payload = await request.json()
    process_paddle_event.delay(payload)
    return {"queued": True}
