import asyncio
from typing import Optional, Dict, Any

from dotenv import load_dotenv
from google.cloud.firestore_v1 import AsyncClient

load_dotenv()

# --- Firestore Initialization ---
_clients: dict = {}

async def get_db() -> AsyncClient:
    """Get or create a Firestore AsyncClient for the current event loop."""
    loop = asyncio.get_running_loop()
    if loop not in _clients:
        _clients[loop] = AsyncClient()
    return _clients[loop]


# --- 2. RESTORED: Firestore Helpers (Native Async) ---

async def get_document(collection_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
    try:
        db = await get_db()
        doc_ref = db.collection(collection_name).document(doc_id)
        doc = await doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            data['id'] = doc.id
            return data
        return None
    except Exception as e:
        print(f"Error getting document '{doc_id}' from '{collection_name}': {e}")
        return None


async def update_document(collection_name: str, doc_id: str, data_to_update: Dict[str, Any]) -> bool:
    try:
        db = await get_db()
        doc_ref = db.collection(collection_name).document(doc_id)
        await doc_ref.set(data_to_update, merge=True)
        return True
    except Exception as e:
        print(f"Error updating document '{doc_id}': {e}")
        return False

