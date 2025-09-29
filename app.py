#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys, subprocess, asyncio, json, os, threading, tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from urllib.parse import urlencode

DEFAULT_API_HTTP = "https://blue51410.dev/api"
TOKEN_PATH = os.path.join(os.path.expanduser("~"), ".bluechat_token.json")

def _bootstrap_pip():
    try:
        import ensurepip
        try:
            ensurepip.bootstrap()
        except Exception:
            pass
    except Exception:
        pass

def _pip_install(pkg):
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user", pkg], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass

_bootstrap_pip()
try:
    import requests
except Exception:
    _pip_install("requests")
    import requests

try:
    import websockets
except Exception:
    _pip_install("websockets")
    import websockets

def save_token(server_base: str, username: str, token: str):
    try:
        with open(TOKEN_PATH, "w", encoding="utf-8") as f:
            json.dump({"server": server_base, "username": username, "token": token}, f)
    except Exception:
        pass

def load_token():
    try:
        with open(TOKEN_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

class RegisterDialog(simpledialog.Dialog):
    def body(self, master):
        ttk.Label(master, text="Create account").grid(row=0, column=0, columnspan=2, pady=(0,6))
        ttk.Label(master, text="Username").grid(row=1, column=0, sticky="e")
        ttk.Label(master, text="Password").grid(row=2, column=0, sticky="e")
        self.e_user = ttk.Entry(master, width=24)
        self.e_pass = ttk.Entry(master, width=24, show="*")
        self.e_user.grid(row=1, column=1, padx=6, pady=2)
        self.e_pass.grid(row=2, column=1, padx=6, pady=2)
        return self.e_user
    def apply(self):
        self.username = self.e_user.get().strip()
        self.password = self.e_pass.get()

class ChatClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Blue Chat")
        self.token = None
        self.username = None
        self.ws = None
        self.ws_task = None
        self.loop = asyncio.new_event_loop()

        frm = ttk.Frame(root, padding=8)
        frm.pack(fill="both", expand=True)

        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(0,6))
        ttk.Label(row, text="Server:").pack(side="left")
        self.server_var = tk.StringVar(value=DEFAULT_API_HTTP)
        ttk.Entry(row, textvariable=self.server_var, width=36).pack(side="left", padx=6)
        ttk.Button(row, text="Check", command=self.check_server).pack(side="left", padx=(4,0))
        ttk.Button(row, text="Register", command=self.open_register).pack(side="left", padx=(4,0))

        row2 = ttk.Frame(frm)
        row2.pack(fill="x", pady=(0,6))
        ttk.Label(row2, text="Username:").pack(side="left")
        self.user_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.user_var, width=18).pack(side="left", padx=6)
        ttk.Label(row2, text="Password:").pack(side="left")
        self.pass_var = tk.StringVar()
        ttk.Entry(row2, textvariable=self.pass_var, width=18, show="*").pack(side="left", padx=6)
        ttk.Button(row2, text="Login", command=self.login).pack(side="left", padx=4)

        row3 = ttk.Frame(frm)
        row3.pack(fill="x", pady=(0,6))
        ttk.Label(row3, text="Room:").pack(side="left")
        self.room_var = tk.StringVar(value="general")
        ttk.Entry(row3, textvariable=self.room_var, width=18).pack(side="left", padx=6)
        self.conn_btn = ttk.Button(row3, text="Connect", command=self.toggle_connection, state="disabled")
        self.conn_btn.pack(side="left", padx=4)

        self.chat = tk.Text(frm, height=20, state="disabled", wrap="word")
        self.chat.pack(fill="both", expand=True, pady=(4,6))
        self.entry_var = tk.StringVar()
        entry = ttk.Entry(frm, textvariable=self.entry_var)
        entry.pack(fill="x")
        entry.bind("<Return>", lambda e: self.send_msg())
        ttk.Button(frm, text="Send", command=self.send_msg).pack(anchor="e", pady=(6,0))

        threading.Thread(target=self._run_loop, daemon=True).start()
        self.try_auto_login()

    def log(self, line: str):
        self.chat.configure(state="normal")
        self.chat.insert("end", line + "\n")
        self.chat.see("end")
        self.chat.configure(state="disabled")

    def api(self, path: str) -> str:
        return self.server_var.get().rstrip("/") + path

    def check_server(self):
        try:
            r = requests.get(self.api("/"), timeout=5)
            if r.ok:
                messagebox.showinfo("OK", "Server online")
            else:
                messagebox.showerror("Error", "Server replied " + str(r.status_code))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_register(self):
        dlg = RegisterDialog(self.root, title="Register")
        username = getattr(dlg, "username", "").strip()
        password = getattr(dlg, "password", "")
        if not username or not password:
            return
        try:
            r = requests.post(self.api("/register"), json={"username": username, "password": password}, timeout=8)
            if r.ok:
                data = r.json()
                self.username = data["username"]
                self.token = data["token"]
                save_token(self.server_var.get().strip(), self.username, self.token)
                self.user_var.set(self.username)
                self.pass_var.set(password)
                self.log("[system] Registered and logged in as " + self.username)
                self.conn_btn.config(state="normal")
            else:
                messagebox.showerror("Register failed", r.text)
        except Exception as e:
            messagebox.showerror("Register failed", str(e))

    def login(self):
        try:
            payload = {"username": self.user_var.get().strip(), "password": self.pass_var.get()}
            r = requests.post(self.api("/login"), json=payload, timeout=8)
            if r.ok:
                data = r.json()
                self.username = data["username"]
                self.token = data["token"]
                save_token(self.server_var.get().strip(), self.username, self.token)
                self.log("[system] Logged in as " + self.username)
                self.conn_btn.config(state="normal")
            else:
                if r.status_code == 401:
                    if messagebox.askyesno("Login failed", "Invalid credentials. Create a new account?"):
                        self.open_register()
                else:
                    messagebox.showerror("Login failed", r.text)
        except Exception as e:
            messagebox.showerror("Login failed", str(e))

    def try_auto_login(self):
        data = load_token()
        if not data:
            return
        srv = data.get("server") or DEFAULT_API_HTTP
        tok = data.get("token")
        usr = data.get("username")
        if not tok or not usr:
            return
        self.server_var.set(srv)
        self.username = usr
        self.token = tok
        self.user_var.set(usr)
        self.conn_btn.config(state="normal")
        self.log("[system] Loaded saved session as " + usr)

    def toggle_connection(self):
        if self.ws:
            self.loop.call_soon_threadsafe(asyncio.create_task, self._disconnect())
        else:
            room = self.room_var.get().strip() or "general"
            self.loop.call_soon_threadsafe(asyncio.create_task, self._connect(room))

    async def _connect(self, room: str):
        if not self.token:
            messagebox.showwarning("Not logged in", "Login or register first.")
            return
        self.conn_btn.config(text="Disconnect")
        base = self.server_var.get().strip().rstrip("/")
        if base.startswith("https://"):
            ws_base = "wss://" + base[len("https://"):]
        elif base.startswith("http://"):
            ws_base = "ws://" + base[len("http://"):]
        else:
            ws_base = base
        url = f"{ws_base}/ws?{urlencode({'token': self.token, 'room': room})}"
        try:
            self.ws = await websockets.connect(url, ping_interval=20, ping_timeout=20)
            self.log("[system] Connected to #" + room)
            self.ws_task = asyncio.create_task(self._receiver())
        except Exception as e:
            self.log("[error] " + str(e))
            self.ws = None
            self.conn_btn.config(text="Connect")

    async def _disconnect(self):
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None
            self.log("[system] Disconnected")
            self.conn_btn.config(text="Connect")

    async def _receiver(self):
        try:
            async for msg in self.ws:
                try:
                    data = json.loads(msg)
                except Exception:
                    self.log(msg)
                    continue
                if data.get("system"):
                    ev = data.get("event")
                    if ev == "history":
                        for m in data.get("messages", []):
                            self.log(f"{m['created_at']}  {m['username']}: {m['content']}")
                    elif ev == "join":
                        self.log("[system] " + str(data.get("username")) + " joined #" + str(data.get("room")))
                    elif ev == "leave":
                        self.log("[system] " + str(data.get("username")) + " left #" + str(data.get("room")))
                else:
                    self.log(f"{data['created_at']}  {data['username']}: {data['content']}")
        except Exception:
            pass
        finally:
            self.ws = None
            self.conn_btn.config(text="Connect")

    def send_msg(self):
        content = self.entry_var.get().strip()
        if not content:
            return
        self.entry_var.set("")
        if not self.ws:
            self.log("[warn] Not connected")
            return
        payload = json.dumps({"content": content})
        self.loop.call_soon_threadsafe(asyncio.create_task, self.ws.send(payload))

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except Exception:
        pass
    ChatClient(root)
    root.mainloop()

if __name__ == "__main__":
    main()
