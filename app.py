import os
from sanhash.web import app

if __name__ == "__main__":
    # Flask's debug mode (the interactive in-browser debugger) must never run on a public
    # deployment — it allows arbitrary code execution if an unhandled error occurs. Set
    # SANHASHER_ENV=production on any real host; local/dev runs keep the debugger by default.
    is_production = os.environ.get("SANHASHER_ENV", "development").lower() == "production"
    port = int(os.environ.get("PORT", 5000))
    host = "0.0.0.0" if is_production else "127.0.0.1"
    app.run(host=host, port=port, debug=not is_production)
