"""FastAPI Production Guard — three executed checks for FastAPI apps.

FPG001  a user-owned resource is looked up by a client-supplied id without
        the current user in the query (IDOR).
FPG002  a webhook handler runs its side effects without deduplicating on the
        provider's event id.
FPG003  a balance (credits, quota, wallet) is read and then written without
        anything serialising concurrent requests.

`scan` finds these in source code; `probe` proves or disproves them against a
running app. Neither asks a language model for an opinion.
"""

__version__ = "0.1.0"
