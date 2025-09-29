#!/usr/bin/env python3
# FastAPI chat API with JWT auth + WebSocket rooms + SQLite storage

import asyncio
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Dict, Set

import jwt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, constr
from passlib.context import CryptContext
import uvicorn

# ====== CONFIG ======
JWT_SECRET = "324625643563456"
JWT_ALG = "HS256"
TOKEN_EXPIRES_HOURS = 48
DB_PATH = "chat.db"
ALLOW_ORIGINS = ["*"]  # lock down later if you want
# ====================

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="Blue Chat API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS messages(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room TEXT NOT NULL,
      username TEXT NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT NOT NULL
    )""")
    conn.commit()
    conn.close()

init_db()

def create_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=TOKEN_EXPIRES_HOURS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(token: str) -> str:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload["sub"]
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

class RegisterBody(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=32)
    password: constr(min_length=6, max_length=128)

class LoginBody(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=32)
    password: constr(min_length=6, max_length=128)

def user_exists(username: str) -> bool:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return bool(row)

def create_user(username: str, password: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users(username, password_hash, created_at) VALUES(?,?,?)",
        (username, pwd_ctx.hash(password), datetime.utcnow().isoformat()+"Z")
    )
    conn.commit()
    conn.close()

def check_password(username: str, password: str) -> bool:
    conn = db()
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    conn.close()
    return bool(row) and pwd_ctx.verify(password, row["password_hash"])

def save_message(room: str, username: str, content: str):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages(room, username, content, created_at) VALUES(?,?,?,?)",
        (room, username, content, datetime.utcnow().isoformat()+"Z")
    )
    conn.commit()
    conn.close()

def fetch_history(room: str, limit: int = 50):
    conn = db()
    cur = conn.cursor()
    cur.execute(
        "SELECT username, content, created_at FROM messages WHERE room=? ORDER BY id DESC LIMIT ?",
        (room, limit)
    )
    rows = cur.fetchall()
    conn.close()
    # return newest->oldest; client can reverse
    return [{"username": r["username"], "content": r["content"], "created_at": r["created_at"]} for r in rows]

@app.get("/")
def root():
    return {"ok": True, "service": "Blue Chat API"}

@app.post("/register")
def register(body: RegisterBody):
    if user_exists(body.username):
        raise HTTPException(status_code=409, detail="Username taken")
    create_user(body.username, body.password)
    token = create_token(body.username)
    return {"token": token, "username": body.username}

@app.post("/login")
def login(body: LoginBody):
    if not user_exists(body.username) or not check_password(body.username, body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(body.username)
    return {"token": token, "username": body.username}

@app.get("/me")
def me(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    username = verify_token(auth.split(" ", 1)[1])
    return {"username": username}

@app.get("/history")
def history(room: str = "general", limit: int = 50):
    limit = max(1, min(limit, 200))
    return {"room": room, "messages": list(reversed(fetch_history(room, limit)))}

# ---- WebSocket manager ----
class RoomHub:
    def __init__(self):
        self.rooms: Dict[str, Set[WebSocket]] = {}
        self.usernames: Dict[WebSocket, str] = {}

    async def connect(self, ws: WebSocket, room: str, username: str):
        await ws.accept()
        self.rooms.setdefault(room, set()).add(ws)
        self.usernames[ws] = username
        await self.broadcast(room, {"system": True, "event": "join", "username": username, "room": room})

    def disconnect(self, ws: WebSocket):
        username = self.usernames.get(ws)
        for room, members in list(self.rooms.items()):
            if ws in members:
                members.remove(ws)
                if not members:
                    del self.rooms[room]
                # fire and forget system message
                asyncio.create_task(self.broadcast(room, {"system": True, "event": "leave", "username": username, "room": room}))
        self.usernames.pop(ws, None)

    async def broadcast(self, room: str, message: dict):
        if room not in self.rooms:
            return
        stale = []
        data = json.dumps(message)
        for ws in list(self.rooms[room]):
            try:
                await ws.send_text(data)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.disconnect(ws)

hub = RoomHub()

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    # Expect query params: ?token=...&room=...
    token = ws.query_params.get("token")
    room = ws.query_params.get("room", "general")
    if not token:
        await ws.close(code=4401)
        return
    try:
        username = verify_token(token)
    except HTTPException:
        await ws.close(code=4401)
        return

    await hub.connect(ws, room, username)
    try:
        # On connect: send recent history
        await ws.send_text(json.dumps({"system": True, "event": "history", "room": room, "messages": fetch_history(room, 50)[::-1]}))

        while True:
            text = await ws.receive_text()
            try:
                payload = json.loads(text)
                content = (payload.get("content") or "").strip()
            except Exception:
                content = text.strip()

            if not content:
                continue

            msg = {
                "system": False,
                "room": room,
                "username": username,
                "content": content,
                "created_at": datetime.utcnow().isoformat()+"Z"
            }
            save_message(room, username, content)
            await hub.broadcast(room, msg)
    except WebSocketDisconnect:
        hub.disconnect(ws)
    except Exception:
        hub.disconnect(ws)
        try:
            await ws.close()
        except Exception:
            pass

if __name__ == "__main__":
    # 0.0.0.0 so it's reachable; change port if needed
    uvicorn.run("server:app", host="0.0.0.0", port=8080, reload=False)
