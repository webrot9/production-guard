from celery import shared_task

from ..models import CreditGrant


@shared_task
def process_paddle_event(payload):
    from .db import SessionLocal

    with SessionLocal() as db:
        db.add(CreditGrant(user_id=payload["data"]["customer_id"], amount=500))
        db.commit()
