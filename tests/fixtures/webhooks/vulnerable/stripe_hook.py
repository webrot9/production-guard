import stripe
from fastapi import APIRouter, Header, Request

from ..models import CreditGrant

router = APIRouter()


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request, stripe_signature: str = Header(alias="Stripe-Signature")):
    payload = await request.body()
    event = stripe.Webhook.construct_event(payload, stripe_signature, "whsec_x")
    if event["type"] == "checkout.session.completed":
        await grant_credits(request.state.db, event["data"]["object"]["client_reference_id"], 100)
    return {"ok": True}


async def grant_credits(db, user_id, amount):
    db.add(CreditGrant(user_id=user_id, amount=amount))
    await db.commit()
