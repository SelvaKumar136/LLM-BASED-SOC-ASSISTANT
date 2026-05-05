"""
Human-in-the-Loop Approval Queue
Falls back to in-memory queue when Redis is unavailable.
"""

import json
import sys


def _safe_print(*args, **kwargs):
    """Print safely on Windows by replacing unencodable characters."""
    text = " ".join(str(a) for a in args)
    sys.stdout.write(text.encode(sys.stdout.encoding or "utf-8", errors="replace").decode(sys.stdout.encoding or "utf-8", errors="replace") + "\n")
    sys.stdout.flush()

# ---------------------------------------------------------------------------
# Try Redis; fall back to a simple in-memory list
# ---------------------------------------------------------------------------
_USE_REDIS = False
_redis_client = None
_memory_queue: list[str] = []          # fallback storage
QUEUE_KEY = "soc:approval_queue"

try:
    import redis
    from config import REDIS_URL
    _redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    _redis_client.ping()
    _USE_REDIS = True
    _safe_print("[HITL] Connected to Redis (ok)")
except Exception:
    _safe_print("[HITL] Redis unavailable - using in-memory queue (data lost on restart)")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def queue_action(action: dict) -> None:
    """Add an action that requires human approval."""
    payload = json.dumps(action)
    if _USE_REDIS:
        _redis_client.rpush(QUEUE_KEY, payload)
    else:
        _memory_queue.append(payload)
    _safe_print(f"  [HITL] Queued: {action.get('action_type')}")


def get_pending_actions() -> list[dict]:
    """Return all actions awaiting approval."""
    if _USE_REDIS:
        items = _redis_client.lrange(QUEUE_KEY, 0, -1)
    else:
        items = list(_memory_queue)
    return [json.loads(i) for i in items]


def approve_action(index: int) -> dict:
    """Approve and execute the action at the given (0-based) index."""
    if _USE_REDIS:
        items = _redis_client.lrange(QUEUE_KEY, 0, -1)
    else:
        items = list(_memory_queue)

    if index < 0 or index >= len(items):
        return {"error": "Invalid index"}

    action = json.loads(items[index])

    if _USE_REDIS:
        try:
            _redis_client.lrem(QUEUE_KEY, 1, items[index])
        except redis.exceptions.ResponseError:
            # Fallback for redis-py 2.x signature
            _redis_client.lrem(QUEUE_KEY, items[index], 1)
    else:
        _memory_queue.pop(index)

    _execute(action)
    return {"status": "executed", "action": action}


def deny_action(index: int) -> dict:
    """Deny and remove the action at the given (0-based) index."""
    if _USE_REDIS:
        items = _redis_client.lrange(QUEUE_KEY, 0, -1)
    else:
        items = list(_memory_queue)

    if index < 0 or index >= len(items):
        return {"error": "Invalid index"}

    action = json.loads(items[index])

    if _USE_REDIS:
        try:
            _redis_client.lrem(QUEUE_KEY, 1, items[index])
        except redis.exceptions.ResponseError:
            # Fallback for redis-py 2.x signature
            _redis_client.lrem(QUEUE_KEY, items[index], 1)
    else:
        _memory_queue.pop(index)

    _safe_print(f"  [HITL] Denied: {action.get('action_type')}")
    return {"status": "denied", "action": action}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _execute(action: dict) -> None:
    """Simulate executing an approved action."""
    t = action.get("action_type")
    if t == "block_ip":
        _safe_print(f"  [EXEC] Blocking IP: {action.get('ip')}")
    elif t == "isolate_host":
        _safe_print(f"  [EXEC] Isolating host: {action.get('hostname')}")
    else:
        _safe_print(f"  [EXEC] Executing: {t}")