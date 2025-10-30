#!/usr/bin/env python3
"""
Simple script to run the FastAPI server for development
"""
import uvicorn

if __name__ == "__main__":
    print("🚀 Starting Chunked File Upload Server...")
    print("📁 Backend running at: http://localhost:8000")
    print("🌐 Frontend: Open frontend/index.html in your browser")
    print("📊 API Docs: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop the server\n")

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
