# 🚀 Chunked File Upload System

A minimal implementation of chunked file upload system that mimics real-world cloud storage services like Google Drive, Dropbox, and AWS S3 multipart uploads.

## 🏗️ Architecture

- **Backend**: FastAPI with three main endpoints for chunked upload
- **Frontend**: Vanilla HTML/JS with 1MB chunk processing
- **Storage**: Local filesystem with temporary chunk storage
- **Tracking**: In-memory upload session management

## 📁 Project Structure

```
HLD/
├── backend/
│   ├── main.py              # FastAPI app with upload endpoints
│   ├── requirements.txt     # Python dependencies
│   ├── run.py              # Development server launcher
│   ├── uploads/            # Temporary chunk storage (auto-created)
│   └── merged/             # Final merged files (auto-created)
├── frontend/
│   └── index.html          # Upload interface with chunking logic
└── README.md
```

## 🚀 Quick Start

### 1. Setup Backend

```bash
# Navigate to backend directory
cd backend

# Install dependencies (using the virtual environment)
source ../hld/bin/activate
pip install -r requirements.txt

# Start the server
python run.py
```

The server will start at `http://localhost:8000`

### 2. Open Frontend

Simply open `frontend/index.html` in your web browser. The frontend will connect to the backend at `http://localhost:8000`.

### 3. Test Upload

1. Select any file (try different sizes: small text files, images, videos)
2. Click "Upload File"
3. Watch the progress as chunks are uploaded sequentially
4. Check the `backend/merged/` directory for the final file

## 🔧 API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `POST /upload/init` | Initialize upload session, returns `upload_id` |
| `POST /upload/chunk` | Upload individual file chunk |
| `POST /upload/complete` | Merge all chunks into final file |
| `GET /upload/status/{upload_id}` | Get upload session status |

## 🧪 Testing Different Scenarios

### Supported File Types
- **DMG Files**: Apple Disk Images (.dmg)
- **Text Files**: Various text formats (.txt, .log, .md, .csv, .json, .xml, .yaml, .yml)

### Small Files (< 1MB)
- Single chunk upload
- Immediate completion
- Works with both DMG and text files

### Large Files (> 1MB)
- Multiple chunks (1MB each)
- Sequential upload with progress tracking
- Automatic merging
- Full encryption and virus scanning

### Edge Cases to Test
- Very large files (100MB+)
- Files with special characters in names
- Duplicate filename handling
- Network interruption simulation
- Mixed text encodings (UTF-8, ASCII, Latin-1)
- Empty files
- Files with virus signatures (for testing quarantine)

## 🎯 Key Features Implemented

✅ **File Chunking**: Splits files into 1MB chunks using `Blob.slice()`  
✅ **Sequential Upload**: Uploads chunks one by one to avoid overwhelming server  
✅ **Progress Tracking**: Real-time progress bar and status updates  
✅ **Session Management**: In-memory tracking of upload sessions  
✅ **File Merging**: Automatic chunk reassembly in correct order  
✅ **Error Handling**: Basic error responses and user feedback  
✅ **Duplicate Handling**: Automatic filename conflict resolution  
✅ **Cleanup**: Automatic temporary file cleanup after merge  
✅ **Multi-Format Support**: DMG disk images and various text file formats  
✅ **Content Detection**: Smart file type detection using magic bytes and heuristics  
✅ **Encryption at Rest**: AES-256-GCM encryption for stored files  
✅ **Virus Scanning**: ClamAV integration for malware detection  
✅ **Quarantine System**: Automatic isolation of infected files  

## 🔮 Future Extensions

This foundation can be extended with:

- **Resumable Uploads**: Resume interrupted uploads
- **Parallel Chunks**: Upload multiple chunks simultaneously  
- **Cloud Storage**: Integration with AWS S3, Google Cloud Storage
- **Database Persistence**: SQLite/PostgreSQL for session tracking
- **Authentication**: User-based upload sessions
- **File Validation**: MIME type checking, virus scanning
- **Compression**: Chunk compression before upload
- **Encryption**: End-to-end encryption for sensitive files

## 🛠️ Development Notes

- **Chunk Size**: Currently set to 1MB (configurable in both frontend and backend)
- **Storage**: Local filesystem (easily replaceable with cloud storage)
- **CORS**: Enabled for development (restrict in production)
- **Memory**: Upload sessions stored in memory (use database for production)

This implementation provides a solid foundation for understanding how modern file upload systems work under the hood!
