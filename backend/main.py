"""Run LOGFORGE FastAPI Backend Server."""
import uvicorn
import sys
import os

# Add root directory to python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    uvicorn.run("backend.api.app:app", host="0.0.0.0", port=8000, reload=True)
