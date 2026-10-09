"""Controlled HTTP double for worker orchestration tests; this is NOT real AI.

Run separately from the worker. Never enable this server in the application stack.
"""

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = {"mode": "valid", "requests": []}
LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, value, status=200):
        payload = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self.send_json({"status": "ok", "implementation": "controlled-http-test-double"})
        elif self.path == "/requests":
            with LOCK:
                self.send_json({"requests": list(STATE["requests"])})
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 1024 * 1024:
                return self.send_json({"error": "invalid size"}, 400)
            body = json.loads(self.rfile.read(length))
            if self.path == "/control":
                if body.get("mode") not in {
                    "valid",
                    "unavailable",
                    "malformed",
                    "identity_mismatch",
                    "partial",
                }:
                    return self.send_json({"error": "invalid mode"}, 400)
                with LOCK:
                    STATE.update(mode=body["mode"], requests=[])
                return self.send_json({"status": "ok"})
            if self.path != "/api/chat":
                return self.send_json({"error": "not found"}, 404)
            columns = json.loads(body["messages"][1]["content"])["columns"]
            with LOCK:
                mode = STATE["mode"]
                STATE["requests"].append({"model": body["model"], "columns": columns})
                number = len(STATE["requests"])
            if mode == "unavailable":
                return self.send_json({"error": "controlled unavailability"}, 503)
            decisions = []
            for column in columns:
                category = next(iter(sorted(column["category_counts"])), "NONE")
                decision = {
                    key: column[key]
                    for key in (
                        "result_id",
                        "schema_name",
                        "table_name",
                        "column_name",
                        "json_path",
                    )
                }
                decision.update(
                    category=category,
                    risk="LOW" if category == "NONE" else "HIGH",
                    recommendation="KEEP" if category == "NONE" else "NULLIFY",
                    confidence=0.87,
                    reason="Controlled HTTP test decision using metadata only.",
                    requires_human_approval=True,
                )
                if mode == "identity_mismatch":
                    decision["column_name"] = "wrong_column"
                decisions.append(decision)
            content = (
                "invalid controlled response"
                if mode == "malformed" or (mode == "partial" and number > 1)
                else json.dumps({"decisions": decisions})
            )
            return self.send_json(
                {
                    "model": body["model"],
                    "message": {"role": "assistant", "content": content},
                    "done": True,
                    "done_reason": "stop",
                }
            )
        except (ValueError, KeyError, TypeError, IndexError):
            return self.send_json({"error": "invalid controlled request"}, 400)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "11434")))
    args = parser.parse_args()
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
