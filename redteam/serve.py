"""Simple HTTP server for the Red Team Ops Security Lab site."""
import http.server
import socketserver
import os
import sys

PORT = 7700
DIR = os.path.dirname(os.path.abspath(__file__))

os.chdir(DIR)

Handler = http.server.SimpleHTTPRequestHandler
Handler.extensions_map.update({'.js': 'application/javascript', '.css': 'text/css', '.html': 'text/html'})

with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
    print(f"RED TEAM OPS serving at http://0.0.0.0:{PORT}")
    print(f"Open http://localhost:{PORT} in your browser")
    httpd.serve_forever()
