"""
Vercel entrypoint.

The @vercel/python runtime imports this file and serves the module-level `app`
WSGI object. We add the project root to sys.path so the `sentinel` package
imports cleanly whether run by Vercel or locally.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from sentinel import create_app  # noqa: E402

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=7000, debug=True)
