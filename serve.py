"""
Local runner. `python serve.py` starts the console at http://127.0.0.1:7000
using SQLite (sentinel.db) unless TIDB_HOST is set in your environment.
"""

from sentinel import create_app

app = create_app()

if __name__ == "__main__":
    print(" * Sentinel console: http://127.0.0.1:7000")
    app.run(host="127.0.0.1", port=7000, debug=True)
