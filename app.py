"""
app.py
======
Entropy Lab: the optional visual dashboard (menu option 10 in main.py).

This is only a display layer. It does no maths of its own: every number it
shows comes from entropy_core.py, the same functions the menu uses.

It needs Flask (pip install flask). The menu-driven application in main.py
does not need it.

Run on its own:
    python app.py
"""

import io
import threading
import webbrowser

from flask import Flask, jsonify, request

import entropy_core as core

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 40 * 1024 * 1024      # uploads up to 40 MB

UPLOADS = {}                                             # non-text files waiting to be analysed


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.get("/api/methods")
def api_methods():
    """The list of methods, so the page can build its buttons."""
    return jsonify([{"id": m.id, "name": m.name, "fam": m.fam} for m in core.METHODS])


@app.post("/api/analyse")
def api_analyse():
    """Run every selected method on the input and return all measurements."""
    body = request.get_json(force=True, silent=True) or {}

    # 1. Get the input as bytes
    token = body.get("file_token")
    binary = token in UPLOADS
    raw = UPLOADS[token] if binary else (body.get("text") or "").encode("utf-8")
    truncated = len(raw) > core.MAX_BYTES
    plain = core.preprocess(raw, body.get("pre", "raw"))

    # 2. Keys and settings
    try:
        shift = int(body.get("shift", 3) or 0)
    except (TypeError, ValueError):
        shift = 0
    ctx = core.Context(shift, body.get("vkey") or "", body.get("passphrase") or "")
    enabled = set(body.get("enabled") or [m.id for m in core.METHODS])

    # 3. Transform with every method and measure each output
    results = []
    for r in core.analyse(plain, ctx, enabled):
        m = r["method"]
        as_text = m.text and not binary
        results.append({
            "id": m.id, "name": m.name, "fam": m.fam,
            "how": m.describe(ctx), "reads": m.reads,
            "n": r["n"], "unique": r["unique"], "H": r["H"], "dH": r["dH"],
            "band": core.classify(r["H"], r["n"]),
            "counts": r["counts"],
            "preview": core.text_preview(r["out"]) if as_text else core.hex_preview(r["out"]),
        })

    # 4. The experiments
    response = {"truncated": truncated, "results": results, "size": None, "noise": None, "limits": [], "hero": None}
    if plain:
        response["size"] = core.size_experiment(plain, ctx)
        response["noise"] = core.noise_experiment(plain)
        response["limits"] = core.limitations(plain, ctx)
        response["hero"] = {"plain": plain[:4096].hex(), "cipher": core.rc4(plain[:4096], ctx.pass_bytes).hex()}
    return jsonify(response)


@app.get("/api/shape")
def api_shape():
    """Entropy of a hand-built distribution: k symbols with a given skew."""
    try:
        k = int(request.args.get("k", 27))
        skew = float(request.args.get("s", 1))
    except ValueError:
        return jsonify({"error": "k must be a whole number and s a number."}), 400
    return jsonify(core.shape_distribution(k, max(0.0, min(5.0, skew))))


@app.post("/api/extract")
def api_extract():
    """Turn an uploaded file into text (PDF or text file) or keep its raw bytes (anything else)."""
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file was received."}), 400
    data = f.read()
    name = f.filename or "file"

    if name.lower().endswith(".pdf") or data[:5] == b"%PDF-":
        try:
            from pypdf import PdfReader                  # optional, only for reading PDF text
        except ImportError:
            return jsonify({"error": "Reading PDF text needs the pypdf package. Install it with: pip install pypdf"}), 400
        try:
            reader = PdfReader(io.BytesIO(data))
            if reader.is_encrypted:
                return jsonify({"error": "That PDF is password-protected, so its text cannot be read."}), 400
            text = "\n".join((page.extract_text() or "") for page in reader.pages).strip()
            pages = len(reader.pages)
        except Exception:
            return jsonify({"error": "That PDF could not be read. It may be damaged."}), 400
        if not text:
            return jsonify({"error": "No selectable text in this PDF. It is probably a scan. Paste the text instead."}), 400
        return jsonify({"kind": "text", "text": text,
                        "label": f"{name} · {pages} page{'' if pages == 1 else 's'} · {len(text):,} characters"})

    try:
        text = data.decode("utf-8")
        if "\x00" in text:
            raise UnicodeDecodeError("utf-8", data, 0, 1, "binary data")
        return jsonify({"kind": "text", "text": text, "label": f"{name} · {len(data):,} bytes"})
    except UnicodeDecodeError:
        UPLOADS.clear()                                  # keep only the latest upload in memory
        token = f"file-{len(data)}-{core.simple_hash(data[:4096])}"
        UPLOADS[token] = data[:core.MAX_BYTES + 1]       # one extra byte so we can tell it was cut
        return jsonify({"kind": "binary", "token": token, "label": f"{name} · {len(data):,} bytes · binary"})


def start(open_browser=True):
    """Start the dashboard. Called by main.py (option 10) or by running this file."""
    url = "http://127.0.0.1:5000"
    print(f"\n  Entropy Lab dashboard is running at {url}\n  Press Ctrl+C to stop.\n")
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    start()
