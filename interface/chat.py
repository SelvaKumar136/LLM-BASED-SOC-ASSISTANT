import sys
import os
# Add the root project directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import chainlit as cl
from langchain_groq import ChatGroq
# ... the rest of your imports stay the same

import chainlit as cl
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage
from memory.vector_store import retrieve_similar
from hitl.approval_queue import get_pending_actions, approve_action, deny_action
from config import GROQ_API_KEY

llm = ChatGroq(
    model="llama-3.1-8b-instant",
    temperature=0,
    api_key=GROQ_API_KEY
)

@cl.on_chat_start
async def start():
    await cl.Message(
        content="👋 SOC Assistant ready! Ask me anything or type **pending** to see actions waiting for approval."
    ).send()

@cl.on_message
async def handle(message: cl.Message):
    text = message.content.lower().strip()

    # 1. Show pending actions
    if text == "pending":
        actions = get_pending_actions()
        if not actions:
            await cl.Message(content="✅ No pending actions.").send()
        else:
            lines = [f"**{i+1}.** `{a['action_type']}` — {a}" for i, a in enumerate(actions)]
            msg = "**⏳ Pending Actions:**\n\n" + "\n".join(lines)
            msg += "\n\nType `approve 1` or `deny 1` to action them."
            await cl.Message(content=msg).send()
        return

    # 2. Handle approve / deny commands
    if text.startswith("approve ") or text.startswith("deny "):
        parts = text.split()
        if len(parts) == 2 and parts[1].isdigit():
            command = parts[0]
            # Convert 1-based UI index to 0-based backend array index
            index = int(parts[1]) - 1 
            
            if command == "approve":
                result = approve_action(index)
                if "error" in result:
                    await cl.Message(content=f"❌ Error: {result['error']}").send()
                else:
                    await cl.Message(content=f"✅ **Approved & Executed:** `{result['action']['action_type']}`").send()
            
            elif command == "deny":
                result = deny_action(index)
                if "error" in result:
                    await cl.Message(content=f"❌ Error: {result['error']}").send()
                else:
                    await cl.Message(content=f"🚫 **Denied:** `{result['action']['action_type']}`").send()
            return

    # 3. Handle general chat queries
    response = llm.invoke([
        SystemMessage(content="You are a helpful SOC assistant. Answer the user's cybersecurity questions directly and concisely."),
        HumanMessage(content=message.content)
    ])
    
    await cl.Message(content=response.content).send()
    