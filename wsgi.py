"""WSGI entry point for production servers.

- gunicorn:         gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120
- PythonAnywhere:    point its generated WSGI file's `application` at the `application`
                     object below (PythonAnywhere's own WSGI loader looks for that name).
- Any other WSGI
  server:            import `app` (or `application`, same object) from this module.

The long --timeout above matters here specifically: finishing a large chunked evidence
upload re-reads the whole assembled file to compute its SHA-256, which can take a while
for very large files, and a default 30s worker timeout would kill that request mid-hash.
"""
from sanhash.web import app

application = app  # the name PythonAnywhere's default WSGI config looks for

if __name__ == "__main__":
    app.run()
