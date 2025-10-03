import os
import asyncio
import logging
from langgraph_sdk import Auth
from langgraph_sdk.auth.types import StudioUser
from supabase import create_client, Client
from typing import Optional, Any

logger = logging.getLogger(__name__)

supabase_url = os.environ.get("SUPABASE_URL")
supabase_key = os.environ.get("SUPABASE_KEY")
supabase: Optional[Client] = None

if supabase_url and supabase_key:
    supabase = create_client(supabase_url, supabase_key)
    logger.info("[Auth] Supabase client initialized")
else:
    logger.warning("[Auth] Supabase client not initialized - missing SUPABASE_URL or SUPABASE_KEY")

# The "Auth" object is a container that LangGraph will use to mark our authentication function
auth = Auth()


# The `authenticate` decorator tells LangGraph to call this function as middleware
# for every request. This will determine whether the request is allowed or not
@auth.authenticate
async def get_current_user(authorization: str | None) -> Auth.types.MinimalUserDict:
    """Check if the user's JWT token is valid using Supabase."""

    # Ensure we have authorization header
    if not authorization:
        logger.warning("[Auth] Authorization header missing")
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Authorization header missing"
        )

    # Parse the authorization header
    try:
        scheme, token = authorization.split()
        assert scheme.lower() == "bearer"
        logger.debug(f"[Auth] Token received, length: {len(token)} chars")
    except (ValueError, AssertionError):
        logger.warning("[Auth] Invalid authorization header format")
        raise Auth.exceptions.HTTPException(
            status_code=401, detail="Invalid authorization header format"
        )

    # Ensure Supabase client is initialized
    if not supabase:
        logger.error("[Auth] Supabase client not initialized")
        raise Auth.exceptions.HTTPException(
            status_code=500, detail="Supabase client not initialized"
        )

    try:
        # Verify the JWT token with Supabase using asyncio.to_thread to avoid blocking
        # This will decode and verify the JWT token in a separate thread
        async def verify_token() -> dict[str, Any]:
            response = await asyncio.to_thread(supabase.auth.get_user, token)
            return response

        response = await verify_token()
        user = response.user

        if not user:
            logger.warning("[Auth] Invalid token or user not found")
            raise Auth.exceptions.HTTPException(
                status_code=401, detail="Invalid token or user not found"
            )

        # Return user info if valid
        logger.info(f"[Auth] User authenticated: {user.id}")
        return {
            "identity": user.id,
        }
    except Auth.exceptions.HTTPException:
        raise
    except Exception as e:
        # Handle any errors from Supabase
        logger.error(f"[Auth] Authentication error: {str(e)}")
        raise Auth.exceptions.HTTPException(
            status_code=401, detail=f"Authentication error: {str(e)}"
        )


@auth.on.threads.create
@auth.on.threads.create_run
async def on_thread_create(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.threads.create.value,
):
    """Add owner when creating threads.

    This handler runs when creating new threads and does two things:
    1. Sets metadata on the thread being created to track ownership
    2. Returns a filter that ensures only the creator can access it
    """

    if isinstance(ctx.user, StudioUser):
        logger.debug("[Auth] Thread create: Studio user, skipping ownership")
        return

    # Add owner metadata to the thread being created
    # This metadata is stored with the thread and persists
    metadata = value.setdefault("metadata", {})
    metadata["owner"] = ctx.user.identity
    logger.debug(f"[Auth] Thread create: Setting owner to {ctx.user.identity}")


@auth.on.threads.read
@auth.on.threads.delete
@auth.on.threads.update
@auth.on.threads.search
async def on_thread_read(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.threads.read.value,
):
    """Only let users read their own threads.

    This handler runs on read operations. We don't need to set
    metadata since the thread already exists - we just need to
    return a filter to ensure users can only see their own threads.
    """
    if isinstance(ctx.user, StudioUser):
        logger.debug("[Auth] Thread access: Studio user, no filter")
        return

    logger.debug(f"[Auth] Thread access: Filtering by owner {ctx.user.identity}")
    return {"owner": ctx.user.identity}


@auth.on.assistants.create
async def on_assistants_create(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.assistants.create.value,
):
    if isinstance(ctx.user, StudioUser):
        logger.debug("[Auth] Assistant create: Studio user, skipping ownership")
        return

    # Add owner metadata to the assistant being created
    # This metadata is stored with the assistant and persists
    metadata = value.setdefault("metadata", {})
    metadata["owner"] = ctx.user.identity
    logger.debug(f"[Auth] Assistant create: Setting owner to {ctx.user.identity}")


@auth.on.assistants.read
@auth.on.assistants.delete
@auth.on.assistants.update
@auth.on.assistants.search
async def on_assistants_read(
    ctx: Auth.types.AuthContext,
    value: Auth.types.on.assistants.read.value,
):
    """Only let users read their own assistants.

    This handler runs on read operations. We don't need to set
    metadata since the assistant already exists - we just need to
    return a filter to ensure users can only see their own assistants.
    """

    if isinstance(ctx.user, StudioUser):
        logger.debug("[Auth] Assistant access: Studio user, no filter")
        return

    logger.debug(f"[Auth] Assistant access: Filtering by owner {ctx.user.identity}")
    return {"owner": ctx.user.identity}


@auth.on.store()
async def authorize_store(ctx: Auth.types.AuthContext, value: dict):
    if isinstance(ctx.user, StudioUser):
        logger.debug("[Auth] Store access: Studio user, no restriction")
        return

    # The "namespace" field for each store item is a tuple you can think of as the directory of an item.
    namespace: tuple = value["namespace"]
    logger.debug(f"[Auth] Store access: Checking namespace {namespace} for user {ctx.user.identity}")
    assert namespace[0] == ctx.user.identity, "Not authorized"
