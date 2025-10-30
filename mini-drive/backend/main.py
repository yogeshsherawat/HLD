import base64
import json
import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path

import pyclamd
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response

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
    "txt": [
        # Text files don't have specific magic bytes, but we can check for common patterns
        # We'll use content-based detection for text files
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

    # Check for text files - use content-based detection
    if is_text_file(file_data):
        return "txt"

    return None


def is_text_file(file_data: bytes, sample_size: int = 1024) -> bool:
    """
    Determine if file data represents a text file by analyzing content.
    Uses heuristics to detect text vs binary content.
    """
    if not file_data:
        return True  # Empty file can be considered text

    # Take a sample from the beginning of the file
    sample = file_data[:sample_size]

    # Check for null bytes (strong indicator of binary file)
    if b"\x00" in sample:
        return False

    # Check for common binary file signatures that we don't support
    binary_signatures = [
        b"\x89PNG",  # PNG
        b"\xff\xd8\xff",  # JPEG
        b"GIF8",  # GIF
        b"PK\x03\x04",  # ZIP
        b"\x50\x4b\x03\x04",  # ZIP variant
        b"\x1f\x8b",  # GZIP
        b"BM",  # BMP
        b"RIFF",  # WAV/AVI
        b"\x00\x00\x01\x00",  # ICO
        b"%PDF",  # PDF
    ]

    for sig in binary_signatures:
        if sample.startswith(sig):
            return False

    # Try to decode as text with common encodings
    try:
        # Try UTF-8 first
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass

    try:
        # Try ASCII
        sample.decode("ascii")
        return True
    except UnicodeDecodeError:
        pass

    try:
        # Try Latin-1 (covers most single-byte encodings)
        sample.decode("latin-1")

        # If it decodes as Latin-1, check if it looks like text
        # Count printable characters vs control characters
        text = sample.decode("latin-1")
        printable_chars = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        printable_ratio = printable_chars / len(text) if text else 0

        # If more than 80% of characters are printable, consider it text
        return printable_ratio > 0.8

    except UnicodeDecodeError:
        return False


def validate_file_type(
    file_data: bytes, expected_filename: str = None
) -> tuple[bool, str]:
    """
    Validate if the file type is allowed based on magic bytes.
    Returns (is_valid, detected_type_or_error_message)
    """
    detected_type = detect_file_type_from_magic_bytes(file_data)

    if detected_type is None:
        return False, "Unsupported file type. Only DMG and TXT files are allowed."

    # Additional filename validation for text files
    if detected_type == "txt" and expected_filename:
        filename_lower = expected_filename.lower()
        if not (
            filename_lower.endswith(".txt")
            or filename_lower.endswith(".log")
            or filename_lower.endswith(".md")
            or filename_lower.endswith(".csv")
            or filename_lower.endswith(".json")
            or filename_lower.endswith(".xml")
            or filename_lower.endswith(".yaml")
            or filename_lower.endswith(".yml")
        ):
            return (
                False,
                f"File detected as text but filename '{expected_filename}' doesn't have a supported text extension (.txt, .log, .md, .csv, .json, .xml, .yaml, .yml)",
            )

    return True, detected_type


# ==================== ENCRYPTION AT REST FUNCTIONS ====================


def generate_file_encryption_key(
    upload_id: str, salt: bytes = None
) -> tuple[bytes, bytes]:
    """
    Generate a unique encryption key for each file using PBKDF2.
    Returns (key, salt) tuple.
    """
    if salt is None:
        salt = os.urandom(32)  # 256-bit salt

    # Use upload_id as password base + server secret
    password = f"{upload_id}_file_encryption_secret".encode("utf-8")

    # Derive 256-bit key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits
        salt=salt,
        iterations=100000,  # OWASP recommended minimum
        backend=default_backend(),
    )
    key = kdf.derive(password)

    return key, salt


def encrypt_data_at_rest(data: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM for storage.
    Returns (encrypted_data, nonce) tuple.
    """
    # Generate random nonce (96 bits for GCM)
    nonce = os.urandom(12)

    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt data
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Return encrypted data with authentication tag appended
    return encrypted_data + encryptor.tag, nonce


def decrypt_data_at_rest(
    encrypted_data_with_tag: bytes, key: bytes, nonce: bytes
) -> bytes:
    """
    Decrypt data that was encrypted with encrypt_data_at_rest.
    """
    # Split encrypted data and authentication tag (last 16 bytes)
    encrypted_data = encrypted_data_with_tag[:-16]
    tag = encrypted_data_with_tag[-16:]

    # Create cipher
    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()

    # Decrypt and verify
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    return decrypted_data


def save_encryption_metadata(
    upload_id: str, salt: bytes, chunk_nonces: dict, final_file_nonce: bytes = None
):
    """
    Save encryption metadata for later decryption.
    """
    metadata = {
        "upload_id": upload_id,
        "salt": base64.b64encode(salt).decode("utf-8"),
        "chunk_nonces": {
            str(k): base64.b64encode(v).decode("utf-8") for k, v in chunk_nonces.items()
        },
        "final_file_nonce": (
            base64.b64encode(final_file_nonce).decode("utf-8")
            if final_file_nonce
            else None
        ),
        "encryption_algorithm": "AES-256-GCM",
        "key_derivation": "PBKDF2-SHA256-100000",
    }

    metadata_path = os.path.join(KEYS_DIR, f"{upload_id}_encryption.json")
    with open(metadata_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"🔐 Saved encryption metadata: {metadata_path}")


def load_encryption_metadata(upload_id: str) -> dict:
    """
    Load encryption metadata for decryption.
    """
    metadata_path = os.path.join(KEYS_DIR, f"{upload_id}_encryption.json")
    if not os.path.exists(metadata_path):
        raise FileNotFoundError(
            f"Encryption metadata not found for upload_id: {upload_id}"
        )

    with open(metadata_path, "r") as f:
        metadata = json.load(f)

    # Decode base64 values
    metadata["salt"] = base64.b64decode(metadata["salt"])
    metadata["chunk_nonces"] = {
        int(k): base64.b64decode(v) for k, v in metadata["chunk_nonces"].items()
    }
    if metadata["final_file_nonce"]:
        metadata["final_file_nonce"] = base64.b64decode(metadata["final_file_nonce"])

    return metadata


# ==================== END ENCRYPTION AT REST FUNCTIONS ====================


# ==================== VIRUS SCANNING FUNCTIONS ====================

# Configuration for virus scanning
VIRUS_SCAN_ENABLED = True  # Set to False to disable virus scanning for testing

# Initialize ClamAV connection
clamd_client = None


def init_clamav():
    """Initialize ClamAV daemon connection"""
    global clamd_client
    try:
        # Try to connect to ClamAV daemon
        clamd_client = pyclamd.ClamdAgnostic()

        # Test connection
        if clamd_client.ping():
            print("🦠 ClamAV daemon connected successfully")

            # Get version info
            version = clamd_client.version()
            print(f"🦠 ClamAV version: {version}")
            return True
        else:
            print("⚠️ ClamAV daemon not responding")
            return False

    except Exception as e:
        print(f"⚠️ Failed to connect to ClamAV daemon: {e}")
        print("💡 Make sure ClamAV daemon is running: brew install clamav && clamd")
        clamd_client = None
        return False


def scan_data_for_virus(
    data: bytes, filename: str = "unknown"
) -> tuple[bool, str, str]:
    """
    Scan data for viruses using ClamAV.
    Returns (is_clean, scan_result, virus_name)
    """
    if not VIRUS_SCAN_ENABLED:
        return True, "SCAN_DISABLED", None

    if clamd_client is None:
        print("⚠️ ClamAV not available - skipping virus scan")
        return True, "SCAN_UNAVAILABLE", None

    try:
        # Scan the data directly
        scan_result = clamd_client.scan_stream(data)

        if scan_result is None:
            # Clean file
            print(f"✅ Virus scan CLEAN: {filename}")
            return True, "CLEAN", None
        else:
            # Virus found
            virus_name = scan_result.get("stream", ["UNKNOWN_VIRUS"])[1]
            print(f"🚨 VIRUS DETECTED in {filename}: {virus_name}")
            return False, "INFECTED", virus_name

    except Exception as e:
        print(f"❌ Virus scan error for {filename}: {e}")
        # In production, you might want to reject files if scanning fails
        # For now, we'll allow them but log the error
        return True, "SCAN_ERROR", str(e)


def scan_file_for_virus(file_path: str) -> tuple[bool, str, str]:
    """
    Scan a file for viruses using ClamAV.
    Returns (is_clean, scan_result, virus_name)
    """
    if not VIRUS_SCAN_ENABLED:
        return True, "SCAN_DISABLED", None

    if clamd_client is None:
        print("⚠️ ClamAV not available - skipping virus scan")
        return True, "SCAN_UNAVAILABLE", None

    try:
        # Scan the file
        scan_result = clamd_client.scan_file(file_path)

        if scan_result is None:
            # Clean file
            print(f"✅ Virus scan CLEAN: {file_path}")
            return True, "CLEAN", None
        else:
            # Virus found
            virus_name = list(scan_result.values())[0][1]
            print(f"🚨 VIRUS DETECTED in {file_path}: {virus_name}")
            return False, "INFECTED", virus_name

    except Exception as e:
        print(f"❌ Virus scan error for {file_path}: {e}")
        return True, "SCAN_ERROR", str(e)


def quarantine_file(file_path: str, upload_id: str, virus_name: str = None) -> str:
    """
    Move infected file to quarantine directory.
    Returns the quarantine path.
    """
    timestamp = int(time.time())
    quarantine_filename = f"{upload_id}_{timestamp}_{os.path.basename(file_path)}"
    quarantine_path = os.path.join(QUARANTINE_DIR, quarantine_filename)

    # Move file to quarantine
    shutil.move(file_path, quarantine_path)

    # Create quarantine metadata
    quarantine_metadata = {
        "original_path": file_path,
        "quarantine_path": quarantine_path,
        "upload_id": upload_id,
        "virus_name": virus_name,
        "quarantined_at": timestamp,
        "status": "QUARANTINED",
    }

    metadata_path = quarantine_path + ".metadata.json"
    with open(metadata_path, "w") as f:
        json.dump(quarantine_metadata, f, indent=2)

    print(f"🔒 File quarantined: {quarantine_path}")
    return quarantine_path


def save_virus_scan_results(upload_id: str, scan_results: dict):
    """Save virus scan results for an upload session"""
    scan_metadata = {
        "upload_id": upload_id,
        "scan_results": scan_results,
        "scanned_at": int(time.time()),
        "clamav_version": clamd_client.version() if clamd_client else "N/A",
    }

    scan_metadata_path = os.path.join(KEYS_DIR, f"{upload_id}_virus_scan.json")
    with open(scan_metadata_path, "w") as f:
        json.dump(scan_metadata, f, indent=2)

    print(f"🦠 Saved virus scan results: {scan_metadata_path}")


# ==================== END VIRUS SCANNING FUNCTIONS ====================


app = FastAPI(title="Chunked File Upload Service", version="1.0.0")

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration - Use relative paths based on current file location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
MERGED_DIR = os.path.join(DATA_DIR, "merged")
KEYS_DIR = os.path.join(DATA_DIR, "keys")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
CHUNK_SIZE = 1024 * 1024  # 1MB

# Ensure directories exist
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(MERGED_DIR, exist_ok=True)
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

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

        # Generate encryption key and salt for this upload
        encryption_key, salt = generate_file_encryption_key(upload_id)

        # Store session info in memory
        upload_sessions[upload_id] = {
            "filename": filename,
            "upload_path": upload_path,
            "chunks_received": set(),
            "total_chunks": None,  # Will be set when we know file size
            "created_at": int(time.time()),
            "file_type_validated": False,  # Track if file type has been validated
            "detected_file_type": None,  # Store detected file type
            # Encryption at rest
            "encryption_key": encryption_key,
            "salt": salt,
            "chunk_nonces": {},  # Store nonce for each chunk
            # Virus scanning
            "virus_scan_results": {},  # Store scan results for each chunk
            "final_scan_result": None,  # Final file scan result
            "is_infected": False,  # Overall infection status
        }
        
        print(f"Upload session initialized: {upload_sessions}")

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

        # Virus scan the decrypted chunk before storing
        is_clean, scan_result, virus_name = scan_data_for_virus(
            decrypted_content, f"chunk_{chunk_index}_{session['filename']}"
        )

        # Store scan result
        session["virus_scan_results"][chunk_index] = {
            "is_clean": is_clean,
            "scan_result": scan_result,
            "virus_name": virus_name,
            "scanned_at": int(time.time()),
        }

        # If virus detected, reject the chunk and potentially quarantine
        if not is_clean and scan_result == "INFECTED":
            session["is_infected"] = True

            # Save the infected chunk for analysis (optional)
            infected_chunk_path = os.path.join(
                session["upload_path"], f"infected_chunk_{chunk_index}"
            )
            with open(infected_chunk_path, "wb") as infected_file:
                infected_file.write(decrypted_content)

            # Quarantine the infected chunk
            quarantine_path = quarantine_file(
                infected_chunk_path, upload_id, virus_name
            )

            # Clean up upload session and reject
            try:
                shutil.rmtree(session["upload_path"])
            except Exception:
                pass
            del upload_sessions[upload_id]

            raise HTTPException(
                status_code=400,
                detail={
                    "error": "VIRUS_DETECTED",
                    "virus_name": virus_name,
                    "chunk_index": chunk_index,
                    "quarantine_path": quarantine_path,
                    "message": f"Virus detected in chunk {chunk_index}: {virus_name}. Upload rejected and file quarantined.",
                },
            )

        # Encrypt chunk data before storing to disk
        encrypted_chunk_data, nonce = encrypt_data_at_rest(
            decrypted_content, session["encryption_key"]
        )

        # Store nonce for this chunk
        session["chunk_nonces"][chunk_index] = nonce

        # Save encrypted chunk to file
        with open(chunk_path, "wb") as chunk_file:
            chunk_file.write(encrypted_chunk_data)

        # Mark chunk as received (only after successful write)
        session["chunks_received"].add(chunk_index)
        print(
            f"Chunk {chunk_index} encrypted and saved to disk (size: {len(encrypted_chunk_data)} bytes)"
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

        # First, merge decrypted chunks into a temporary file
        temp_final_path = final_path + ".temp"
        with open(temp_final_path, "wb") as temp_final_file:
            for chunk_index in range(session["total_chunks"]):
                chunk_path = os.path.join(
                    session["upload_path"], f"chunk_{chunk_index}"
                )
                if not os.path.exists(chunk_path):
                    raise HTTPException(
                        status_code=500,
                        detail=f"Chunk file missing: chunk_{chunk_index}",
                    )

                # Read encrypted chunk from disk
                with open(chunk_path, "rb") as chunk_file:
                    encrypted_chunk_data = chunk_file.read()

                # Decrypt chunk using stored nonce
                chunk_nonce = session["chunk_nonces"][chunk_index]
                decrypted_chunk_data = decrypt_data_at_rest(
                    encrypted_chunk_data, session["encryption_key"], chunk_nonce
                )

                # Write decrypted chunk to temporary final file
                temp_final_file.write(decrypted_chunk_data)

        # Virus scan the final merged file before encrypting
        print("🦠 Performing final virus scan on merged file...")
        is_clean, scan_result, virus_name = scan_file_for_virus(temp_final_path)

        # Store final scan result
        session["final_scan_result"] = {
            "is_clean": is_clean,
            "scan_result": scan_result,
            "virus_name": virus_name,
            "scanned_at": int(time.time()),
        }

        # If virus detected in final file, quarantine and reject
        if not is_clean and scan_result == "INFECTED":
            session["is_infected"] = True

            # Quarantine the final file
            quarantine_path = quarantine_file(temp_final_path, upload_id, virus_name)

            # Save virus scan results before cleanup
            save_virus_scan_results(
                upload_id,
                {
                    "chunk_results": session["virus_scan_results"],
                    "final_result": session["final_scan_result"],
                    "overall_status": "INFECTED",
                },
            )

            # Clean up upload session
            try:
                shutil.rmtree(session["upload_path"])
            except Exception:
                pass
            del upload_sessions[upload_id]

            raise HTTPException(
                status_code=400,
                detail={
                    "error": "VIRUS_DETECTED_FINAL",
                    "virus_name": virus_name,
                    "quarantine_path": quarantine_path,
                    "message": f"Virus detected in final merged file: {virus_name}. Upload rejected and file quarantined.",
                },
            )

        # Now encrypt the entire final file
        with open(temp_final_path, "rb") as temp_file:
            final_file_data = temp_file.read()

        # Encrypt final file for storage
        encrypted_final_data, final_nonce = encrypt_data_at_rest(
            final_file_data, session["encryption_key"]
        )

        # Write encrypted final file
        with open(final_path, "wb") as final_file:
            final_file.write(encrypted_final_data)

        # Clean up temporary file
        os.remove(temp_final_path)

        # Save encryption metadata for future decryption
        save_encryption_metadata(
            upload_id, session["salt"], session["chunk_nonces"], final_nonce
        )

        # Save virus scan results for successful upload
        save_virus_scan_results(
            upload_id,
            {
                "chunk_results": session["virus_scan_results"],
                "final_result": session["final_scan_result"],
                "overall_status": "CLEAN",
            },
        )

        print(
            f"🔐 Final file encrypted and saved: {final_path} (encrypted size: {len(encrypted_final_data)} bytes)"
        )
        print(f"🦠 Virus scan completed - File is CLEAN")

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


@app.get("/download/{upload_id}")
def download_file(upload_id: str):
    """Decrypt and serve the final file"""
    try:
        # Load encryption metadata
        metadata = load_encryption_metadata(upload_id)

        # Find the encrypted file
        # We need to search for files that match this upload_id
        encrypted_files = []
        for filename in os.listdir(MERGED_DIR):
            file_path = os.path.join(MERGED_DIR, filename)
            if os.path.isfile(file_path):
                # Check if this file was created by this upload_id
                # We can check the metadata to see if it exists
                encrypted_files.append((filename, file_path))

        if not encrypted_files:
            raise HTTPException(
                status_code=404, detail="No files found for this upload"
            )

        # For now, take the first file (in production, you'd have better file tracking)
        filename, file_path = encrypted_files[0]

        # Read encrypted file
        with open(file_path, "rb") as f:
            encrypted_data = f.read()

        # Regenerate encryption key from metadata
        encryption_key, _ = generate_file_encryption_key(upload_id, metadata["salt"])

        # Decrypt file
        decrypted_data = decrypt_data_at_rest(
            encrypted_data, encryption_key, metadata["final_file_nonce"]
        )

        # Return decrypted file data

        return Response(
            content=decrypted_data,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Length": str(len(decrypted_data)),
            },
        )

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt file: {str(e)}")


@app.get("/files")
def list_encrypted_files():
    """List all encrypted files with their metadata"""
    try:
        files = []

        # List all encryption metadata files
        for metadata_file in os.listdir(KEYS_DIR):
            if metadata_file.endswith("_encryption.json"):
                upload_id = metadata_file.replace("_encryption.json", "")

                try:
                    metadata = load_encryption_metadata(upload_id)

                    # Find corresponding encrypted file
                    encrypted_file_path = None
                    encrypted_file_size = 0

                    for filename in os.listdir(MERGED_DIR):
                        file_path = os.path.join(MERGED_DIR, filename)
                        if os.path.isfile(file_path):
                            # Simple heuristic: if file was created around the same time
                            # In production, you'd have better file tracking
                            encrypted_file_path = filename
                            encrypted_file_size = os.path.getsize(file_path)
                            break

                    files.append(
                        {
                            "upload_id": upload_id,
                            "filename": encrypted_file_path,
                            "encrypted_size": encrypted_file_size,
                            "encryption_algorithm": metadata["encryption_algorithm"],
                            "key_derivation": metadata["key_derivation"],
                            "download_url": f"/download/{upload_id}",
                        }
                    )

                except Exception as e:
                    print(f"Error loading metadata for {upload_id}: {e}")
                    continue

        return JSONResponse({"encrypted_files": files, "total_files": len(files)})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list files: {str(e)}")


@app.get("/virus-scan/status/{upload_id}")
def get_virus_scan_status(upload_id: str):
    """Get detailed virus scan results for an upload"""
    try:
        scan_metadata_path = os.path.join(KEYS_DIR, f"{upload_id}_virus_scan.json")
        if not os.path.exists(scan_metadata_path):
            raise HTTPException(status_code=404, detail="Virus scan results not found")

        with open(scan_metadata_path, "r") as f:
            scan_data = json.load(f)

        return JSONResponse(scan_data)

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to get virus scan status: {str(e)}"
        )


@app.get("/quarantine")
def list_quarantined_files():
    """List all quarantined files"""
    try:
        quarantined_files = []

        for filename in os.listdir(QUARANTINE_DIR):
            if filename.endswith(".metadata.json"):
                metadata_path = os.path.join(QUARANTINE_DIR, filename)
                with open(metadata_path, "r") as f:
                    metadata = json.load(f)
                quarantined_files.append(metadata)

        return JSONResponse(
            {
                "quarantined_files": quarantined_files,
                "total_quarantined": len(quarantined_files),
            }
        )

    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to list quarantined files: {str(e)}"
        )


@app.get("/virus-scan/health")
def virus_scan_health():
    """Check ClamAV daemon health and status"""
    try:
        if clamd_client is None:
            return JSONResponse(
                {
                    "status": "unavailable",
                    "message": "ClamAV daemon not connected",
                    "scanning_enabled": VIRUS_SCAN_ENABLED,
                }
            )

        # Test connection
        if clamd_client.ping():
            version = clamd_client.version()
            return JSONResponse(
                {
                    "status": "healthy",
                    "version": version,
                    "scanning_enabled": VIRUS_SCAN_ENABLED,
                    "message": "ClamAV daemon is running and responsive",
                }
            )
        else:
            return JSONResponse(
                {
                    "status": "unhealthy",
                    "message": "ClamAV daemon not responding",
                    "scanning_enabled": VIRUS_SCAN_ENABLED,
                }
            )

    except Exception as e:
        return JSONResponse(
            {
                "status": "error",
                "message": f"Error checking ClamAV status: {str(e)}",
                "scanning_enabled": VIRUS_SCAN_ENABLED,
            }
        )


# Initialize ClamAV on startup
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    print("🚀 Starting Chunked File Upload Service with Virus Scanning...")

    # Initialize ClamAV
    clamav_status = init_clamav()
    if clamav_status:
        print("✅ Virus scanning is ENABLED and ready")
    else:
        print("⚠️ Virus scanning is DISABLED - ClamAV not available")
        print("💡 To enable virus scanning:")
        print("   1. Install ClamAV: brew install clamav")
        print("   2. Update virus definitions: freshclam")
        print("   3. Start daemon: clamd")

    print(f"📁 Base directory: {BASE_DIR}")
    print(f"📁 Data directory: {DATA_DIR}")
    print(f"📁 Upload directory: {UPLOAD_DIR}")
    print(f"📁 Merged files directory: {MERGED_DIR}")
    print(f"🔒 Quarantine directory: {QUARANTINE_DIR}")
    print(f"🔑 Keys directory: {KEYS_DIR}")
