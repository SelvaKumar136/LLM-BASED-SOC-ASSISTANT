import os
from dotenv import load_dotenv

load_dotenv()

# LLM
GROQ_API_KEY       = os.getenv("GROQ_API_KEY")
GROQ_MODEL         = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

# Threat Intelligence
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY  = os.getenv("ABUSEIPDB_API_KEY")

# Infrastructure
REDIS_URL          = os.getenv("REDIS_URL", "redis://localhost:6379")
CHROMA_PATH        = os.getenv("CHROMA_PATH", "./chroma_db")

# Logging
LOG_LEVEL          = os.getenv("LOG_LEVEL", "INFO")