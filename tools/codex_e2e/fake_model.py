#!/usr/bin/env python3
"""A stand-in model server for Codex, stdlib only. It speaks just enough of the Responses API
streaming format for codex exec to run one tool call, so hooks can be tested with zero usage.

python fake_model.py --port 8765 --log DIR [--plan shell|text]

Plan shell: the first request answers with one call to Codex's shell tool that writes
fake-model-wrote.txt in the working directory; the request that carries the tool result
answers with a short assistant message. Every request body is saved to DIR for inspection.
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

COUNTER = itertools.count(1)


def sse(event: dict) -> bytes:
    return f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode()


def pick_shell_call(tools: list, cmd_text: str):
    """Return (name, arguments_json) for the first shell-like tool the request offers."""
    by_name = {}
    for t in tools or []:
        name = t.get("name") or (t.get("function") or {}).get("name")
        if name:
            by_name[name] = t
    for name in ("shell_command", "exec_command", "shell", "container.exec", "local_shell"):
        if name in by_name:
            params = (by_name[name].get("parameters") or {}).get("properties", {})
            if "command" in params and params["command"].get("type") == "string":
                return name, {"command": cmd_text}
            if "cmd" in params:
                return name, {"cmd": cmd_text}
            if "command" in params:  # array form
                if os.name == "nt":
                    return name, {"command": ["powershell.exe", "-NoProfile", "-Command", cmd_text]}
                return name, {"command": ["bash", "-lc", cmd_text]}
    return None, None


class Handler(BaseHTTPRequestHandler):
    server_version = "fake-model/1"

    def log_message(self, fmt, *args):
        sys.stderr.write("fake-model: " + (fmt % args) + "\n")

    def do_GET(self):
        n = next(COUNTER)
        (self.server.logdir / f"{n:03d}-GET.txt").write_text(self.path, encoding="utf-8")
        if self.path.rstrip("/").endswith("/models"):
            body = json.dumps({"object": "list", "data": [{"id": "fake-model", "object": "model"}],
                               "models": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        n = next(COUNTER)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        (self.server.logdir / f"{n:03d}-POST-{self.path.strip('/').replace('/', '_')}.json").write_text(
            json.dumps({"path": self.path, "headers": {k: v for k, v in self.headers.items()
                                                       if k.lower() not in ("authorization",)},
                        "body": body}, indent=2), encoding="utf-8")
        inputs = body.get("input") or []
        has_tool_output = any(isinstance(i, dict) and i.get("type", "").endswith("_output") for i in inputs)
        rid = f"resp_fake_{n}"
        events = [{"type": "response.created", "response": {"id": rid}}]
        name = None
        if self.server.plan == "shell" and not has_tool_output:
            name, args = pick_shell_call(body.get("tools"), self.server.command)
        if name:
            item = {"type": "function_call", "id": f"fc_{n}", "call_id": f"call_{n}", "name": name,
                    "arguments": json.dumps(args)}
            events.append({"type": "response.output_item.added", "output_index": 0, "item": item})
            events.append({"type": "response.output_item.done", "output_index": 0, "item": item})
        else:
            text = "fake model: done" if has_tool_output else "fake model: ok"
            item = {"type": "message", "id": f"msg_{n}", "role": "assistant", "status": "completed",
                    "content": [{"type": "output_text", "text": text, "annotations": []}]}
            events.append({"type": "response.output_item.added", "output_index": 0, "item": item})
            events.append({"type": "response.output_text.delta", "output_index": 0, "content_index": 0,
                           "item_id": item["id"], "delta": text})
            events.append({"type": "response.output_item.done", "output_index": 0, "item": item})
        events.append({"type": "response.completed",
                       "response": {"id": rid, "status": "completed",
                                    "usage": {"input_tokens": 1, "input_tokens_details": {"cached_tokens": 0},
                                              "output_tokens": 1, "output_tokens_details": {"reasoning_tokens": 0},
                                              "total_tokens": 2}}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for e in events:
            self.wfile.write(sse(e))
            self.wfile.flush()
        with open(self.server.logdir / "replies.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps({"n": n, "tool_output_seen": has_tool_output, "reply": name or "message"}) + "\n")


def serve(port: int, logdir: Path, plan: str, command: str):
    logdir.mkdir(parents=True, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.logdir, srv.plan, srv.command = logdir, plan, command
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def provider_args(port: int) -> list[str]:
    """codex -c overrides that point the session at this server for one invocation only."""
    table = ('{name="fake", base_url="http://127.0.0.1:%d/v1", wire_api="responses", '
             'requires_openai_auth=false, request_max_retries=0, stream_max_retries=0}' % port)
    return ["-c", f"model_providers.fake={table}", "-c", 'model_provider="fake"', "-m", "fake-model"]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--log", default="fake-model-log")
    ap.add_argument("--plan", default="shell", choices=["shell", "text"])
    ap.add_argument("--command", default="echo written-by-fake-model > fake-model-wrote.txt")
    a = ap.parse_args()
    s = serve(a.port, Path(a.log), a.plan, a.command)
    print("serving on", a.port, "codex args:", " ".join(provider_args(a.port)), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.shutdown()
