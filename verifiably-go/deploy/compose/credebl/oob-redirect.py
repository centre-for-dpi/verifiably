import http.server
import urllib.request
import json

MINIO = "http://credebl-minio:9000/credebl-bucket"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            data = urllib.request.urlopen(MINIO + self.path).read()
            oob_url = json.loads(data)
            self.send_response(302)
            self.send_header("Location", oob_url)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
        except Exception as e:
            self.send_error(502, str(e))

    def log_message(self, fmt, *args):
        pass

http.server.HTTPServer(("", 3011), Handler).serve_forever()
