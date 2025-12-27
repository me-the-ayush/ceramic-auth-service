import json
import os
from google.cloud import firestore
from google.cloud.exceptions import NotFound as FirestoreNotFound
from google.cloud import storage
from google.cloud.exceptions import NotFound as GCSNotFound
import datetime
from typing import Optional, List, Dict, Any
import uuid
from dotenv import load_dotenv
import asyncio
from functools import partial

load_dotenv()

# --- Firestore Initialization ---
db = firestore.Client()
print("Firestore client initialized.")

# --- Google Cloud Storage Configuration and Client Initialization ---
GCS_BUCKET_NAME = "uploaded-blogs-images"  # <--- **MAKE SURE THIS IS YOUR ACTUAL BUCKET NAME**

try:
    storage_client = storage.Client()
    gcs_bucket = storage_client.bucket(GCS_BUCKET_NAME)
    print(f"GCS client initialized and connected to bucket: {GCS_BUCKET_NAME}")
except Exception as e:
    print(f"ERROR: Failed to initialize Google Cloud Storage client or connect to bucket '{GCS_BUCKET_NAME}': {e}")
    raise RuntimeError(f"Failed to connect to Google Cloud Storage bucket: {e}")


# --- Generic Helper Functions for Firestore Operations ---

def _get_collection_ref(collection_name: str) -> firestore.CollectionReference:
    """Returns a synchronous Firestore collection reference."""
    return db.collection(collection_name)


async def get_document(collection_name: str, doc_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetches a single document from a Firestore collection by its ID.
    Returns the document data as a dictionary, or None if not found.
    """
    loop = asyncio.get_event_loop()  # Get the current event loop
    try:
        doc_ref = _get_collection_ref(collection_name).document(doc_id)
        # Run the synchronous get() in a separate thread
        doc = await loop.run_in_executor(None, doc_ref.get)
        if doc.exists:
            data = doc.to_dict()
            data['id'] = doc.id  # Add Firestore ID to the dictionary
            return data
        return None
    except Exception as e:
        print(f"Error getting document '{doc_id}' from '{collection_name}': {e}")
        return None


async def add_document_to_collection(collection_name: str, document_data: Dict[str, Any]) -> str:
    """
    Adds a new document to a Firestore collection with an auto-generated ID.
    Returns the ID of the newly created document.
    """
    loop = asyncio.get_event_loop()
    try:
        collection_ref = _get_collection_ref(collection_name)
        # Run the synchronous add() in a separate thread
        # Note: collection_ref.add returns a tuple (update_time, DocumentReference)
        update_time, doc_ref = await loop.run_in_executor(None, collection_ref.add, document_data)
        return doc_ref.id
    except Exception as e:
        print(f"Error adding document to '{collection_name}': {e}")
        raise


async def update_document(collection_name: str, doc_id: str, data_to_update: Dict[str, Any]) -> bool:
    """
    Updates an existing document in a Firestore collection.
    If the document does not exist, it will be created (upsert).
    Uses merge=True to update specific fields without overwriting the entire document.
    """
    loop = asyncio.get_event_loop()
    try:
        doc_ref = _get_collection_ref(collection_name).document(doc_id)
        # Use functools.partial to bind arguments to doc_ref.set
        set_func = partial(doc_ref.set, data_to_update, merge=True)
        await loop.run_in_executor(None, set_func)

        print(f"Document '{doc_id}' in '{collection_name}' updated successfully.")
        return True
    except Exception as e:
        print(f"Error updating document '{doc_id}' in '{collection_name}': {e}")
        return False


async def delete_document_by_id(collection_name: str, doc_id: str) -> bool:
    """
    Deletes a single document from a Firestore collection by its ID.
    Returns True if deleted, False if not found or error.
    """
    loop = asyncio.get_event_loop()
    try:
        doc_ref = _get_collection_ref(collection_name).document(doc_id)
        # Run the synchronous delete() in a separate thread
        await loop.run_in_executor(None, doc_ref.delete)
        return True
    except FirestoreNotFound:
        print(f"Document with ID '{doc_id}' not found in collection '{collection_name}' for deletion.")
        return False
    except Exception as e:
        print(f"Error deleting document '{doc_id}' from '{collection_name}': {e}")
        return False

async def delete_file_from_gcs(image_url: str) -> bool:
    """
    Deletes a file from Google Cloud Storage given its public URL.
    Extracts the blob name from the URL.
    """
    loop = asyncio.get_event_loop()
    if not image_url:
        return False

    try:
        expected_prefix = f"https://storage.googleapis.com/{GCS_BUCKET_NAME}/"
        if not image_url.startswith(expected_prefix):
            print(f"Warning: Image URL '{image_url}' does not match expected GCS bucket prefix. Skipping deletion.")
            return False

        blob_name = image_url.replace(expected_prefix, "")

    except Exception as e:
        print(f"Error parsing image URL for deletion: {e}")
        return False

    blob = gcs_bucket.blob(blob_name)
    try:
        # Check existence and delete in executor
        if await loop.run_in_executor(None, blob.exists):
            await loop.run_in_executor(None, blob.delete)
            print(f"Deleted GCS object: {blob_name}")
            return True
        else:
            print(f"GCS object not found for deletion: {blob_name}")
            return False
    except GCSNotFound:
        print(f"GCS object not found (NotFound exception): {blob_name}")
        return False
    except Exception as e:
        print(f"Error deleting GCS object {blob_name}: {e}")
        return False




async def query_collection(
        collection_name: str,
        conditions: Optional[List[Dict[str, Any]]] = None,
        order_by: Optional[List[Dict[str, str]]] = None,
        limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Queries a Firestore collection with optional conditions, ordering, and limit.
    Conditions format: [{"field": "fieldName", "op": "==", "value": "fieldValue"}]
    Order_by format: [{"field": "fieldName", "direction": "asc"|"desc"}]
    """
    loop = asyncio.get_event_loop()
    collection_ref = _get_collection_ref(collection_name)
    query = collection_ref

    if conditions:
        for condition in conditions:
            field = condition["field"]
            op = condition["op"]
            value = condition["value"]
            query = query.where(field, op, value)

    if order_by:
        for order in order_by:
            field = order["field"]
            direction = firestore.Query.ASCENDING if order.get("direction",
                                                               "asc") == "asc" else firestore.Query.DESCENDING
            query = query.order_by(field, direction=direction)

    if limit:
        query = query.limit(limit)

    docs_data = []
    try:
        # Run the synchronous stream() in a separate thread
        docs_iterator = await loop.run_in_executor(None, query.stream)
        # Iterate synchronously after getting the iterator in the executor.
        for doc in docs_iterator:
            data = doc.to_dict()
            data['id'] = doc.id
            docs_data.append(data)
    except Exception as e:
        print(f"Error querying collection '{collection_name}': {e}")
    return docs_data

