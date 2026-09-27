import json
import os
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type")
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(length) or b"{}")
            source = payload.get("code", "")
            if not isinstance(source, str) or not source.strip():
                self._json({"error": "Code is required"}, 400)
                return

            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script = os.path.join(root, "lib", "deobf.py")
            with tempfile.TemporaryDirectory() as directory:
                input_path = os.path.join(directory, "input.lua")
                output_path = os.path.join(directory, "output.lua")
                with open(input_path, "w", encoding="utf-8") as input_file:
                    input_file.write(source)
                result = subprocess.run(
                    ["python3", script, input_path, "-o", output_path],
                    capture_output=True,
                    text=True,
                    timeout=55,
                )
                if result.returncode != 0:
                    self._json({"error": result.stderr.strip() or "Deobfuscation failed"}, 422)
                    return
                with open(output_path, "r", encoding="utf-8") as output_file:
                    self._json({"code": output_file.read()}, 200)
        except subprocess.TimeoutExpired:
            self._json({"error": "Deobfuscation timed out"}, 504)
        except Exception as error:
            self._json({"error": str(error)}, 500)

    def _json(self, body, status):
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(encoded)
