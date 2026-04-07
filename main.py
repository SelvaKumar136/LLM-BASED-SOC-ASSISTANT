import uvicorn

if __name__ == "__main__":
    print("🚀 Starting SOC Assistant...")
    print("📡 http://localhost:8000")
    print("📖 Docs at http://localhost:8000/docs")
    uvicorn.run(
        "ingest.webhook:app",
        host="0.0.0.0",
        port=8001,
        reload=False
    )