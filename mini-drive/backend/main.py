import base64
import os
import shutil
import uuid
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Magic byte signatures for supported file types
MAGIC_BYTES = {
    "dmg": [
        # Mach-O executable signatures (common in DMG files)
        b"\xfe\xed\xfa\xce",  # 32-bit big-endian Mach-O
        b"\xfe\xed\xfa\xcf",  # 64-bit big-endian Mach-O
        b"\xce\xfa\xed\xfe",  # 32-bit little-endian Mach-O
        b"\xcf\xfa\xed\xfe",  # 64-bit little-endian Mach-O
        # Other DMG signatures
        b"\x78\x01\x73\x0d\x62\x62\x60",  # DMG compressed
        b"\x78\x9c",  # DMG zlib compressed
        b"koly",  # DMG trailer signature (sometimes at beginning)
        b"\x00\x00\x01\x00",  # Some DMG variants
        # Apple Disk Image signatures
        b"BZh",  # bzip2 compressed DMG
        b"\x1f\x8b",  # gzip compressed DMG
    ],
}


def detect_file_type_from_magic_bytes(file_data: bytes) -> str:
    """
    Detect file type based on magic bytes from the beginning of file data.
    Returns the detected file type or None if not supported.
    """
    # Check DMG - need to check multiple possible signatures at the beginning
    for signature in MAGIC_BYTES["dmg"]:
        if file_data.startswith(signature):
            return "dmg"

    return None


def validate_file_type(
    file_data: bytes, expected_filename: str = None
) -> tuple[bool, str]:
    """
    Validate if the file type is allowed based on magic bytes.
    Returns (is_valid, detected_type_or_error_message)
    """
    detected_type = detect_file_type_from_magic_bytes(file_data)

    if detected_type is None:
        return False, "Unsupported file type. Only DMG files are allowed."

    return True, detected_type


app = FastAPI(title="Chunked File Upload Service", version="1.0.0")

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
UPLOAD_DIR = "/Users/yogeshwar.sherawat/yogesh/HLD/backend/data/uploads"
MERGED_DIR = "/Users/yogeshwar.sherawat/yogesh/HLD/backend/data/merged"
KEYS_DIR = "/Users/yogeshwar.sherawat/yogesh/HLD/backend/data/keys"
CHUNK_SIZE = 1024 * 1024  # 1MB

# Ensure directories exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(MERGED_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)

# Generate or load RSA key pair
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public_key.pem")


def generate_or_load_keys():
    """Generate RSA key pair or load existing ones"""
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        # Load existing keys
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
        with open(PUBLIC_KEY_PATH, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        print("🔑 Loaded existing RSA key pair")
    else:
        # Generate new keys
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        public_key = private_key.public_key()

        # Save private key
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
        print("🔑 Generated new RSA key pair")

    return private_key, public_key


# Initialize encryption keys
PRIVATE_KEY, PUBLIC_KEY = generate_or_load_keys()

# In-memory storage for upload sessions
upload_sessions = {}


@app.get("/")
def root():
    return {"message": "Chunked File Upload Service", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/public-key")
def get_public_key():
    """Return the server's public key for client-side encryption"""
    public_key_pem = PUBLIC_KEY.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "public_key": base64.b64encode(public_key_pem).decode("utf-8"),
        "key_size": 2048,
        "algorithm": "RSA",
    }


@app.post("/upload/init")
def init_upload(filename: str = Form(...)):
    """Initialize a new upload session"""
    try:
        # Generate unique upload ID
        upload_id = str(uuid.uuid4())

        # Create directory for this upload session
        upload_path = os.path.join(UPLOAD_DIR, upload_id)
        os.makedirs(upload_path, exist_ok=True)

        # Store session info in memory
        upload_sessions[upload_id] = {
            "filename": filename,
            "upload_path": upload_path,
            "chunks_received": set(),
            "total_chunks": None,  # Will be set when we know file size
            "created_at": None,  # Could add timestamp if needed
            "file_type_validated": False,  # Track if file type has been validated
            "detected_file_type": None,  # Store detected file type
        }

        return JSONResponse(
            {
                "upload_id": upload_id,
                "message": "Upload session initialized",
                "chunk_size": CHUNK_SIZE,
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to initialize upload: {str(e)}"
        )


@app.post("/upload/chunk")
async def upload_chunk(
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    file: UploadFile = File(...),
):
    """Upload a single chunk of the file"""
    try:
        print(upload_sessions)
        # Validate upload session exists
        if upload_id not in upload_sessions:
            raise HTTPException(status_code=404, detail="Upload session not found")

        session = upload_sessions[upload_id]

        # Update total chunks if not set
        if session["total_chunks"] is None:
            session["total_chunks"] = total_chunks
        elif session["total_chunks"] != total_chunks:
            raise HTTPException(status_code=400, detail="Total chunks mismatch")

        # Validate chunk index
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise HTTPException(status_code=400, detail="Invalid chunk index")

        # Check if chunk already received (both in memory AND on disk)
        chunk_path = os.path.join(session["upload_path"], f"chunk_{chunk_index}")
        chunk_exists_on_disk = os.path.exists(chunk_path)
        chunk_in_memory = chunk_index in session["chunks_received"]

        if chunk_in_memory and chunk_exists_on_disk:
            return JSONResponse(
                {
                    "message": "Chunk already received",
                    "chunk_index": chunk_index,
                    "chunks_received": len(session["chunks_received"]),
                    "total_chunks": total_chunks,
                }
            )
        elif chunk_in_memory and not chunk_exists_on_disk:
            # Memory says we have it, but file is missing - remove from memory and re-upload
            session["chunks_received"].discard(chunk_index)
            print(
                f"Warning: Chunk {chunk_index} was in memory but missing from disk. Allowing re-upload."
            )
        elif not chunk_in_memory and chunk_exists_on_disk:
            # File exists but not in memory - add to memory and skip upload
            session["chunks_received"].add(chunk_index)
            print(
                f"Info: Chunk {chunk_index} found on disk but not in memory. Added to tracking."
            )
            return JSONResponse(
                {
                    "message": "Chunk already exists on disk",
                    "chunk_index": chunk_index,
                    "chunks_received": len(session["chunks_received"]),
                    "total_chunks": total_chunks,
                }
            )

        # Read and decrypt chunk content
        encrypted_content = await file.read()
        decrypted_content = None

        try:
            # Decrypt the chunk content using private key
            decrypted_content = PRIVATE_KEY.decrypt(
                encrypted_content,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            print(f"Chunk {chunk_index} decrypted successfully.")
        except Exception as decrypt_error:
            print(f"Decryption failed for chunk {chunk_index}: {decrypt_error}")
            # If decryption fails, use encrypted content as-is (for backward compatibility)
            decrypted_content = encrypted_content
            print(f"Chunk {chunk_index} using fallback mode (no decryption).")

        # Validate file type on first chunk (chunk_index == 0)
        if chunk_index == 0 and not session["file_type_validated"]:
            print(f"Validating file type for first chunk...")
            is_valid, result = validate_file_type(
                decrypted_content, session["filename"]
            )

            if not is_valid:
                # Remove the upload session and cleanup
                try:
                    shutil.rmtree(session["upload_path"])
                except Exception:
                    pass
                del upload_sessions[upload_id]

                raise HTTPException(
                    status_code=400,
                    detail=f"File validation failed: {result}. Detected magic bytes: {decrypted_content[:20].hex() if len(decrypted_content) >= 20 else decrypted_content.hex()}",
                )

            # Mark as validated and store detected type
            session["file_type_validated"] = True
            session["detected_file_type"] = result
            print(f"File type validated successfully: {result}")

        # Save chunk to file
        with open(chunk_path, "wb") as chunk_file:
            chunk_file.write(decrypted_content)

        # Mark chunk as received (only after successful write)
        session["chunks_received"].add(chunk_index)
        print(
            f"Chunk {chunk_index} successfully saved to disk and added to memory tracking."
        )

        return JSONResponse(
            {
                "message": "Chunk uploaded successfully",
                "chunk_index": chunk_index,
                "chunks_received": len(session["chunks_received"]),
                "total_chunks": total_chunks,
                "upload_complete": len(session["chunks_received"]) == total_chunks,
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to upload chunk: {str(e)}")


@app.post("/upload/complete")
def complete_upload(upload_id: str = Form(...)):
    """Merge all chunks into the final file"""
    try:
        # Validate upload session exists
        if upload_id not in upload_sessions:
            raise HTTPException(status_code=404, detail="Upload session not found")

        session = upload_sessions[upload_id]

        # Check if all chunks are received
        if session["total_chunks"] is None:
            raise HTTPException(status_code=400, detail="No chunks uploaded yet")

        # Verify chunks exist on disk (not just in memory)
        chunks_on_disk = []
        for chunk_index in range(session["total_chunks"]):
            chunk_path = os.path.join(session["upload_path"], f"chunk_{chunk_index}")
            if os.path.exists(chunk_path):
                chunks_on_disk.append(chunk_index)

        # Calculate missing chunks based on disk reality
        missing_chunks = sorted(
            list(set(range(session["total_chunks"])) - set(chunks_on_disk))
        )

        print(
            f"Complete Upload - Chunks on disk: {len(chunks_on_disk)}/{session['total_chunks']}"
        )
        if len(missing_chunks) > 0:
            print(f"Missing chunks: {missing_chunks}")

        if len(missing_chunks) > 0:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "Missing chunks detected",
                    "missing_chunks": missing_chunks,
                    "chunks_received": len(chunks_on_disk),
                    "total_chunks": session["total_chunks"],
                    "message": f"Cannot complete upload. Missing {len(missing_chunks)} chunk(s): {missing_chunks}. Please re-upload missing chunks.",
                },
            )

        # Create final file path
        final_filename = session["filename"]
        final_path = os.path.join(MERGED_DIR, final_filename)

        # Handle filename conflicts by adding a number
        counter = 1
        base_name, ext = os.path.splitext(final_filename)
        while os.path.exists(final_path):
            final_filename = f"{base_name}_{counter}{ext}"
            final_path = os.path.join(MERGED_DIR, final_filename)
            counter += 1

        print(f"Final path: {final_path}")
        # Merge chunks in order
        with open(final_path, "wb") as final_file:
            for chunk_index in range(session["total_chunks"]):
                chunk_path = os.path.join(
                    session["upload_path"], f"chunk_{chunk_index}"
                )
                if not os.path.exists(chunk_path):
                    raise HTTPException(
                        status_code=500,
                        detail=f"Chunk file missing: chunk_{chunk_index}",
                    )

                with open(chunk_path, "rb") as chunk_file:
                    final_file.write(chunk_file.read())

        # Get file size for response
        file_size = os.path.getsize(final_path)

        # Clean up chunk files and session
        try:
            shutil.rmtree(session["upload_path"])
        except Exception as cleanup_error:
            print(f"Warning: Failed to cleanup chunks: {cleanup_error}")

        # Remove session from memory
        del upload_sessions[upload_id]

        return JSONResponse(
            {
                "message": "File upload completed successfully",
                "filename": final_filename,
                "file_path": final_path,
                "file_size": file_size,
                "total_chunks": session["total_chunks"],
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to complete upload: {str(e)}"
        )


@app.get("/upload/status/{upload_id}")
def get_upload_status(upload_id: str):
    """Get the current status of an upload session"""
    if upload_id not in upload_sessions:
        raise HTTPException(status_code=404, detail="Upload session not found")

    session = upload_sessions[upload_id]

    # Calculate missing chunks by checking both memory AND file system
    missing_chunks = []
    chunks_on_disk = []

    if session["total_chunks"] is not None:
        all_chunks = set(range(session["total_chunks"]))

        # Check which chunks actually exist on disk
        for chunk_index in range(session["total_chunks"]):
            chunk_path = os.path.join(session["upload_path"], f"chunk_{chunk_index}")
            if os.path.exists(chunk_path):
                chunks_on_disk.append(chunk_index)

        # Missing chunks are those not found on disk
        missing_chunks = sorted(list(all_chunks - set(chunks_on_disk)))

        # Update in-memory tracking to match disk reality
        session["chunks_received"] = set(chunks_on_disk)

    return JSONResponse(
        {
            "upload_id": upload_id,
            "filename": session["filename"],
            "chunks_received": len(chunks_on_disk),
            "total_chunks": session["total_chunks"],
            "is_complete": session["total_chunks"] is not None
            and len(missing_chunks) == 0,
            "missing_chunks": missing_chunks,
            "received_chunks": sorted(chunks_on_disk),
            "file_type_validated": session["file_type_validated"],
            "detected_file_type": session["detected_file_type"],
        }
    )
