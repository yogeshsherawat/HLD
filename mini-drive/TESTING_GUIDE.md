# 🧪 Testing Guide - Chunked File Upload with Retry Mechanism

This guide shows you how to test the robust chunk retry mechanism that handles missing or corrupted chunks.

## 🎯 Features to Test

1. **Normal Upload Flow** - All chunks upload successfully
2. **Missing Chunk Detection** - System detects missing chunks from disk
3. **Automatic Retry** - Re-upload only missing chunks
4. **Status Checking** - Verify upload state at any time

---

## 📋 Test Scenarios

### ✅ Scenario 1: Normal Upload (Happy Path)

**Steps:**
1. Select a file (e.g., 5MB file = 5 chunks)
2. Click "Upload File"
3. Wait for all chunks to upload
4. Click "Complete Upload"
5. ✅ Success! File merged

**Expected Result:** Upload completes successfully, file appears in `backend/merged/`

---

### 🔴 Scenario 2: Manually Delete Chunks to Test Detection

**Steps:**
1. Select and upload a file (e.g., 5MB)
2. After all chunks upload, **DON'T click Complete yet**
3. Open Terminal and manually delete some chunks:
   ```bash
   cd backend/uploads
   ls  # Find your upload_id directory
   cd <upload_id>
   rm chunk_1 chunk_3  # Delete specific chunks
   ```
4. Back in browser, click "Check Status"
5. System detects: "Missing chunks: [1, 3]"
6. Click "Retry Missing Chunks"
7. Watch as only chunks 1 and 3 are re-uploaded
8. Click "Complete Upload"
9. ✅ Success!

**Expected Result:** 
- Status check identifies exact missing chunks
- Retry only uploads missing chunks (not all)
- Completion succeeds after retry

---

### 🧪 Scenario 3: Try Completing with Missing Chunks

**Steps:**
1. Upload a file (e.g., 3MB = 3 chunks)
2. Manually delete `chunk_1` from disk:
   ```bash
   cd backend/uploads/<upload_id>
   rm chunk_1
   ```
3. Click "Complete Upload" directly (without checking status)
4. Backend responds: "Cannot complete. Missing chunk(s): [1]"
5. Frontend automatically shows "Retry Missing Chunks" button
6. Click "Retry Missing Chunks"
7. Click "Complete Upload" again
8. ✅ Success!

**Expected Result:**
- Backend detects missing chunks during completion attempt
- Error message includes specific chunk numbers
- Frontend offers immediate retry option

---

### 🔄 Scenario 4: Check Status Multiple Times

**Steps:**
1. Upload a 10MB file (10 chunks)
2. Delete chunks 2, 5, 8 from disk
3. Click "Check Status" → Shows: "Missing: [2, 5, 8]"
4. Retry chunk 2 only (modify code or manually upload)
5. Click "Check Status" again → Shows: "Missing: [5, 8]"
6. Retry remaining chunks
7. Click "Check Status" → Shows: "Complete: Yes ✅"
8. Click "Complete Upload"
9. ✅ Success!

**Expected Result:**
- Status updates reflect real-time disk state
- Can check status multiple times
- Status is always accurate

---

## 🔧 How It Works

### Backend Verification (Disk-Based)

The backend now checks **actual files on disk**, not just in-memory tracking:

```python
# /upload/status/{upload_id} checks:
for chunk_index in range(total_chunks):
    chunk_path = f"uploads/{upload_id}/chunk_{chunk_index}"
    if os.path.exists(chunk_path):
        chunks_on_disk.append(chunk_index)

missing_chunks = all_chunks - chunks_on_disk
```

### Frontend Retry Logic

The frontend intelligently re-uploads only missing chunks:

```javascript
async function retryMissingChunks(missingChunks) {
    for (const chunkIndex of missingChunks) {
        // Re-slice file at specific chunk position
        const start = chunkIndex * CHUNK_SIZE;
        const end = Math.min(selectedFile.size, start + CHUNK_SIZE);
        const chunk = selectedFile.slice(start, end);
        
        // Upload just this chunk
        await uploadChunk(uploadId, chunkIndex, totalChunks, chunk);
    }
}
```

---

## 🎮 Interactive Testing Commands

### 1. Start Backend
```bash
cd backend
source ../hld/bin/activate
python run.py
```

### 2. Open Frontend
Open `frontend/index.html` in your browser

### 3. Monitor Backend Logs
Watch the terminal for:
- Chunk upload confirmations
- Missing chunk detection logs
- Completion status

### 4. Simulate Missing Chunks
```bash
# Find active upload sessions
ls backend/uploads/

# Delete specific chunks
cd backend/uploads/<upload_id>
rm chunk_0  # Delete first chunk
rm chunk_2  # Delete third chunk

# Check what's left
ls -la
```

---

## 📊 API Endpoints for Testing

### Check Status
```bash
curl http://localhost:8000/upload/status/<upload_id>
```

**Response:**
```json
{
  "upload_id": "abc-123",
  "filename": "test.pdf",
  "chunks_received": 3,
  "total_chunks": 5,
  "is_complete": false,
  "missing_chunks": [1, 3],
  "received_chunks": [0, 2, 4]
}
```

### Try Completion
```bash
curl -X POST http://localhost:8000/upload/complete \
  -F "upload_id=<upload_id>"
```

**Response (if chunks missing):**
```json
{
  "detail": {
    "error": "Missing chunks detected",
    "missing_chunks": [1, 3],
    "chunks_received": 3,
    "total_chunks": 5,
    "message": "Cannot complete upload. Missing 2 chunk(s): [1, 3]. Please re-upload missing chunks."
  }
}
```

---

## 🐛 Debugging Tips

1. **Check backend logs** - Look for:
   - "Complete Upload - Chunks on disk: X/Y"
   - "Missing chunks: [...]"

2. **Verify chunk files exist**:
   ```bash
   ls -la backend/uploads/<upload_id>/
   ```

3. **Check file sizes**:
   ```bash
   ls -lh backend/uploads/<upload_id>/
   # Each chunk should be ~1MB (1048576 bytes)
   ```

4. **Monitor browser console** - Look for:
   - Upload progress
   - Error messages
   - Retry attempts

---

## ✨ Key Benefits of This Approach

✅ **Resilient** - Handles network failures and interruptions  
✅ **Efficient** - Only re-uploads missing chunks  
✅ **Transparent** - Shows exactly which chunks are missi  
✅ **Real-time** - Checks actual disk state, not just memory  
✅ **User-friendly** - One-click retry with automatic detection  

This is exactly how production systems like AWS S3 Multipart Upload and Google Drive handle large file uploads!

