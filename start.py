#!/usr/bin/env python
"""Start script for Railway deployment"""
import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"Starting CloudSentinel API on port {port}")
    uvicorn.run(
        "src.api.routes:app",
        host="0.0.0.0",
        port=port,
        log_level="info"
    )
