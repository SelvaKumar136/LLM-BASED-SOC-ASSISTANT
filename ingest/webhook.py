from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
from ingest.normalizer import normalize_alert

app = FastAPI()


@app.get("/")
def home():
    return {"message": "🚀 LLM SOC Assistant is Running!"}


@app.get("/health")
def health():
    return {"status": "running"}


class RawAlert(BaseModel):
    source:   str
    raw_data: dict


@app.post("/ingest/alert")
async def receive_alert(alert: RawAlert, background_tasks: BackgroundTasks):
    normalized = normalize_alert(alert.source, alert.raw_data)
    from agents.supervisor import run_investigation
    background_tasks.add_task(run_investigation, normalized)
    return {"status": "received", "alert_id": normalized["alert_id"]}