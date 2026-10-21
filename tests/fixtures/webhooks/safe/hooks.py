import stripe
from fastapi import APIRouter, Header, Request
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import IntegrityError

from ..models import CreditGrant, ProcessedEvent

router = APIRouter()


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request, stripe_signature: str = Header(alias="Stripe-Signature")):
    event = stripe.Webhook.construct_event(await request.body(), stripe_signature, "whsec_x")
    db = request.state.db
    claimed = await db.execute(
        insert(ProcessedEvent).values(provider="stripe", event_id=event["id"]).on_conflict_do_nothing()
    )
    if claimed.rowcount == 0:
        return {"duplicate": True}
    db.add(CreditGrant(user_id="u", amount=100))
    await db.commit()


@router.post("/webhooks/paddle")
async def paddle_webhook(request: Request):
    payload = await request.json()
    db = request.state.db
    db.add(ProcessedEvent(provider="paddle", event_id=payload.get("event_id")))
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return {"idempotent": True}
    db.add(CreditGrant(user_id="u", amount=500))


@router.post("/webhooks/github")
async def github_webhook(request: Request, x_github_delivery: str = Header()):
    redis = request.app.state.redis
    if not await redis.set(f"gh:{x_github_delivery}", 1, nx=True, ex=86400):
        return {"duplicate": True}
    await open_issue(await request.json())


async def open_issue(payload): ...


@router.post("/webhooks/clerk")
async def clerk_webhook(request: Request, svix_id: str = Header(alias="svix-id")):
    db = request.state.db
    # Check-then-insert is safe here: the UNIQUE constraint turns the race
    # into an IntegrityError, the transaction rolls back and Svix retries.
    if await db.get(ProcessedEvent, svix_id):
        return {"duplicate": True}
    db.add(ProcessedEvent(provider="clerk", event_id=svix_id))
    await db.commit()


HANDLERS = {"subscription.created": None}


@router.post("/webhooks/resend")
async def resend_webhook(request: Request):
    return await dispatch(await request.json(), request.state.db)


async def dispatch(event, db):
    db.add(ProcessedEvent(provider="resend", event_id=event["id"]))
    try:
        await db.flush()
    except IntegrityError:
        return None
    return {"ok": True}


@router.post("/webhooks/legacy")  # fpg: ignore[FPG002] the legacy provider never retries (fixture)
async def legacy(request: Request):
    request.state.db.add(CreditGrant(user_id="u", amount=1))
