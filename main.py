"""
main.py
=======
Entropy Lab: the menu-driven application.
P6: Entropy-Based Analysis of Encrypted Data.

Run:
    python main.py

Needs nothing but Python itself. All the maths is in entropy_core.py.
Every screen ends with a "What this means" box in plain English.
"""

import math
import os
import sys

import entropy_core as core

# Never crash on a console that cannot show a character: print "?" instead.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(errors="replace")

WIDTH = 78
BAR = 30                    # width of the text bar charts


# ===========================================================================
# Colour (optional). Plain text is used when the console cannot show colour.
# ===========================================================================
class Colour:
    on = False
    CODES = {"green": "32", "amber": "33", "red": "31", "cyan": "36", "bold": "1", "dim": "2"}


def colour_supported():
    if os.environ.get("NO_COLOR") or not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        os.system("")                       # switches on colour codes in the Windows console
    return True


def paint(text, style):
    if not Colour.on or style not in Colour.CODES:
        return text
    return "\033[" + Colour.CODES[style] + "m" + text + "\033[0m"


def zone_style(entropy):
    """Green for low entropy, amber for the middle, red for random-looking."""
    if entropy < 5.5:
        return "green"
    if entropy < 6.5:
        return "amber"
    return "red"


# ===========================================================================
# Console helpers
# ===========================================================================
def line(char="-"):
    print(char * WIDTH)


def title(text):
    print()
    line("=")
    print(" " + paint(text, "bold"))
    line("=")


def ask(prompt, default=""):
    """Read one line. Empty input gives the default. Ctrl+D / Ctrl+Z exits cleanly."""
    try:
        answer = input(prompt).strip()
    except EOFError:
        print()
        raise SystemExit
    return answer or default


def ask_number(prompt, low, high, default):
    """Keep asking until the user gives a whole number in range."""
    while True:
        raw = ask(f"{prompt} [{default}]: ", str(default))
        try:
            value = int(raw)
        except ValueError:
            print(f"  Please type a whole number from {low} to {high}.")
            continue
        if low <= value <= high:
            return value
        print(f"  Please type a whole number from {low} to {high}.")


def pause():
    ask("\nPress Enter to return to the menu...")


def bar(value, maximum, width=BAR, style=None):
    """A text bar, e.g. '#########.....' for value out of maximum."""
    if maximum <= 0:
        return "." * width
    filled = int(round(width * value / maximum))
    filled = max(0, min(width, filled))
    return paint("#" * filled, style) + "." * (width - filled)


def ebar(entropy, width=BAR):
    """A bar for an entropy value on the 0 to 8 scale, coloured by zone."""
    return bar(entropy, 8, width, zone_style(entropy))


def show_byte(value):
    """How one byte value is printed in tables."""
    if value == 32:
        return "0x20 space"
    if value == 10:
        return "0x0A newline"
    if 33 <= value < 127:
        return f"0x{value:02X} '{chr(value)}'"
    return f"0x{value:02X}"


def wrap_lines(text, width):
    """Split text into lines no longer than width."""
    lines, current = [], ""
    for word in text.split():
        if current and len(current) + 1 + len(word) > width:
            lines.append(current)
            current = word
        else:
            current = (current + " " + word) if current else word
    if current:
        lines.append(current)
    return lines


def explain(*paragraphs):
    """The 'What this means' box: plain-English reading of the screen above."""
    inner = WIDTH - 4
    print()
    print(paint("+-- What this means " + "-" * (WIDTH - 21) + "+", "cyan"))
    first = True
    for paragraph in paragraphs:
        if not first:
            print(paint("|", "cyan") + " " * (WIDTH - 2) + paint("|", "cyan"))
        first = False
        for text in wrap_lines(paragraph, inner):
            print(paint("|", "cyan") + " " + text.ljust(inner) + " " + paint("|", "cyan"))
    print(paint("+" + "-" * (WIDTH - 2) + "+", "cyan"))


ZONES = [(0.0, 2.0, "repetitive"), (2.0, 5.5, "text-like"), (5.5, 6.5, "encoded"), (6.5, 8.0, "random")]


def gauge(entropy, label="your data", width=64):
    """A labelled 0-8 scale with named zones and a marker for the value."""
    pos = lambda v: int(round(v / 8 * width))
    pad = "    "
    ticks = [" "] * (width + 4)
    for v, text in ((0, "0"), (2, "2"), (5.5, "5.5"), (6.5, "6.5"), (8, "8")):
        p = pos(v) - (len(text) // 2 if v else 0)
        p = min(p, width + 1 - len(text) + 1)
        for i, ch in enumerate(text):
            ticks[p + i] = ch
    track = ""
    names = [" "] * (width + 1)
    for low, high, name in ZONES:
        a, b = pos(low), pos(high)
        style = zone_style((low + high) / 2)
        track += paint("|" + "=" * (b - a - 1), style)
        start = a + (b - a - len(name)) // 2
        if b - a > len(name):
            for i, ch in enumerate(name):
                names[start + i] = ch
    track += "|"
    marker = [" "] * (width + 1)
    m = pos(max(0.0, min(8.0, entropy)))
    marker[m] = "^"
    note = f"{label}: {entropy:.2f}"
    text_start = m + 2 if m + 2 + len(note) <= width + 1 else max(0, m - 1 - len(note))
    for i, ch in enumerate(note):
        if text_start + i < len(marker) and marker[text_start + i] == " ":
            marker[text_start + i] = ch
    print(pad + "".join(ticks).rstrip())
    print(pad + track)
    print(pad + "".join(names).rstrip())
    print(pad + paint("".join(marker).rstrip(), zone_style(entropy)))


SHADES = " .:-=+*#%@"


def print_byte_map(counts, heading=True):
    """All 256 byte values as a 16 x 16 grid. Darker = appears more often."""
    grid = core.byte_map(counts)
    if heading:
        print("     " + "".join(f"{c:X} " for c in range(16)) + "   <- second hex digit")
    for row in range(16):
        cells = "".join(SHADES[level] * 2 for level in grid[row])
        print(f"  {row:X}x " + cells + " |")
    print("     shades: ' ' never appears   . : - = + * # % @  more and more often")


def step_box(lines):
    for text in lines:
        print("  " + text)


# ===========================================================================
# The application state
# ===========================================================================
class State:
    def __init__(self):
        self.raw = core.DEMO_TEXT.encode("utf-8")   # data before preprocessing
        self.label = "English paragraph (built-in sample)"
        self.mode = "raw"                           # raw | az
        self.shift = 3
        self.vkey = "SECURE"
        self.passphrase = "entropy-lab-demo"

    def data(self):
        return core.preprocess(self.raw, self.mode)

    def ctx(self):
        return core.Context(self.shift, self.vkey, self.passphrase)


def need_data(state):
    """Print a message and return True when there is nothing to analyse."""
    if len(state.data()) == 0:
        print("There is no data. Load some first (option 1).")
        pause()
        return True
    return False


# ===========================================================================
# 1. Load data
# ===========================================================================
def read_file(path):
    """Return (bytes, note). PDFs give their text if the optional pypdf package is installed."""
    with open(path, "rb") as f:
        data = f.read()
    if path.lower().endswith(".pdf"):
        try:
            from pypdf import PdfReader          # optional, only for reading PDF text
        except ImportError:
            return data, "pypdf is not installed, so the PDF's raw bytes are used. (pip install pypdf to read its text.)"
        try:
            pages = PdfReader(path).pages
            text = "\n".join((page.extract_text() or "") for page in pages).strip()
        except Exception:
            return data, "The PDF text could not be read, so its raw bytes are used."
        if text:
            return text.encode("utf-8"), f"Text extracted from {len(pages)} page(s)."
        return data, "No selectable text in this PDF (probably a scan), so its raw bytes are used."
    return data, ""


def menu_load(state):
    title("1. LOAD DATA")
    print("  1. Type or paste text")
    print("  2. Open a file (text, PDF or any other file)")
    print("  3. Pick a built-in sample")
    print("  0. Back")
    choice = ask("\nChoose: ")

    if choice == "1":
        text = ask("\nType your text and press Enter:\n> ")
        if not text:
            print("Nothing typed. The data was not changed.")
            pause()
            return
        state.raw = text.encode("utf-8")
        state.label = "Typed text"

    elif choice == "2":
        path = ask("\nFile path: ").strip('"')
        if not path:
            return
        try:
            data, note = read_file(path)
        except OSError as error:
            print(f"Could not open that file: {error.strerror or error}")
            pause()
            return
        if len(data) == 0:
            print("That file is empty. The data was not changed.")
            pause()
            return
        state.raw = data
        state.label = "File: " + path
        if note:
            print(note)
        if len(data) > core.MAX_BYTES:
            print(f"The file is large, so only the first {core.MAX_BYTES:,} bytes are analysed.")

    elif choice == "3":
        samples = core.sample_collection(state.ctx())
        print()
        for i in range(len(samples)):
            print(f"  {i + 1:>2}. {samples[i][0]}")
        number = ask_number("\nSample number", 1, len(samples), 3)
        state.label = samples[number - 1][0] + " (built-in sample)"
        state.raw = samples[number - 1][1]
    else:
        return

    p = core.profile(state.data())
    print(f"\nLoaded: {state.label}")
    print(f"{p['n']:,} bytes, {p['unique']} distinct values, entropy {p['H']:.3f} bits per byte\n")
    gauge(p["H"])
    explain("Data is loaded. Every option in the menu now works on it.",
            "Option 4 gives the full statistical profile and a verdict on what kind of data this is.")
    pause()


# ===========================================================================
# 2. Byte frequencies and entropy, step by step
# ===========================================================================
def menu_frequency(state):
    title("2. BYTE FREQUENCIES AND ENTROPY, STEP BY STEP")
    if need_data(state):
        return
    data = state.data()
    rows = core.frequency_table(data)
    total = len(data)
    print(f"Data: {state.label}")
    print(f"N = {total:,} bytes, {len(rows)} distinct values\n")
    print("Step 1: count each byte value.   Step 2: p = count / N.")
    print("Step 3: each value adds  -p x log2(p)  to the entropy.\n")
    print(f"{'Byte':<14}{'Count':>8}{'p':>9}{'-p log2 p':>11}  Share")
    line()
    shown = min(15, len(rows))
    top = rows[0][2]
    subtotal = 0.0
    for value, count, p, part in rows[:shown]:
        subtotal += part
        print(f"{show_byte(value):<14}{count:>8}{p:>9.4f}{part:>11.4f}  {bar(p, top, 24)}")
    entropy = 0.0
    for row in rows:
        entropy += row[3]
    if len(rows) > shown:
        print(f"... {len(rows) - shown} more values add {entropy - subtotal:.4f}")
    line()
    ceiling = math.log2(len(rows)) if len(rows) > 1 else 0.0
    entropy_text = paint(format(entropy, ".4f"), zone_style(entropy))
    print(f"H = sum of the last column = {entropy_text} bits per byte")
    print(f"Ceiling for {len(rows)} distinct values: log2({len(rows)}) = {ceiling:.4f}")
    print(f"Ceiling for bytes: log2(256) = 8.0000, so this data reaches {entropy / 8 * 100:.1f}% of it\n")
    gauge(entropy)

    print("\nByte map: all 256 values, one cell each. Row = first hex digit, column = second.\n")
    print_byte_map(core.count_bytes(data))
    most = rows[0]
    explain(
        f"Entropy is {entropy:.2f} bits per byte. Each byte here carries about {entropy:.1f} bits of surprise, "
        f"out of a possible 8.",
        f"The most common value is {show_byte(most[0])}, at {most[2] * 100:.1f}% of all bytes. "
        f"The more one value dominates, the lower the entropy.",
        "In the byte map, ordinary text shows a few dark clusters (letters and spaces) and lots of empty cells. "
        "Encrypted or random data fills the whole grid with an even grey.")
    pause()


# ===========================================================================
# 3. Entropy map: where in the data is it random?
# ===========================================================================
def menu_entropy_map(state):
    title("3. ENTROPY MAP: WHERE IN THE DATA IS IT RANDOM?")
    if need_data(state):
        return
    data = state.data()
    print("The data is cut into windows and entropy is measured in each one.")
    print("Encrypted or compressed parts stand out as high-entropy windows.\n")
    if len(data) < 512:
        print(f"This data is only {len(data):,} bytes, so the map has just one or two windows.")
        number = len(core.sample_collection(state.ctx()))
        print(f"Try the built-in sample 'Mixed file: text + encrypted' (option 1, then 3, then {number}).\n")
    window = ask_number("Window size in bytes (64 to 4096)", 64, 4096, 256)
    windows = core.entropy_map(data, window)
    print()
    print(f"{'Bytes':>17}  {'H':>6}  0 {'':<{BAR - 4}} 8")
    line()
    shown = windows if len(windows) <= 24 else windows[::max(1, len(windows) // 24)]
    for start, length, h in shown:
        print(f"{start:>8,}-{start + length:<8,} {h:>6.2f}  {ebar(h)}")
    if len(shown) < len(windows):
        print(f"(showing {len(shown)} of {len(windows)} windows; the strip below shows all of them)")
    line()
    strip = ""
    for start, length, h in windows:
        strip += paint(SHADES[min(9, int(h / 8 * 9.99))], zone_style(h))
    print("Whole data, left to right:  [" + strip + "]")
    print("                             darker character = higher entropy\n")

    regions = core.high_entropy_regions(windows)
    if not regions:
        found = "No window reached random-looking entropy (6.3 or more). Nothing here looks encrypted."
    elif len(regions) == 1 and regions[0][0] == 0 and regions[0][1] >= len(data):
        found = "Every window is high. The whole data looks encrypted, compressed or random."
    else:
        parts = []
        for start, end in regions:
            parts.append(f"bytes {start:,} to {end:,}")
        found = "High-entropy region found: " + "; ".join(parts) + ". The rest has lower entropy."
    print(found)
    explain(
        "A single entropy number averages the whole file. A file that is half text and half encrypted gets a "
        "middle value that describes neither half.",
        "The map measures each part separately, so you can see where the random-looking data starts and stops. "
        "Forensic tools use the same idea to find hidden or encrypted sections inside files.",
        f"Windows here are {windows[0][1]:,} bytes. Smaller windows show more detail but read lower, because of "
        "the sample-size effect (option 7).")
    pause()


# ===========================================================================
# 4. Full statistical profile and verdict
# ===========================================================================
def menu_profile(state):
    title("4. FULL STATISTICAL PROFILE AND VERDICT")
    if need_data(state):
        return
    data = state.data()
    p = core.profile(data)
    ref = core.random_reference(p["n"])
    print(f"Data: {state.label}  ({p['n']:,} bytes)\n")
    print("Each measure is compared with random data of the SAME size.\n")
    print(f"{'Measure':<26}{'Your data':>11}{'Random data':>13}   What it tells you")
    line()
    rows = [
        ("Shannon entropy", f"{p['H']:.3f}", f"{ref['H']:.3f}", "average unpredictability"),
        ("Min-entropy", f"{p['min_H']:.3f}", f"{ref['min_H']:.3f}", "worst case: best single guess"),
        ("Order check", f"{p['order_H']:.3f}", f"{ref['order_H']:.3f}", "does each byte predict the next?"),
        ("Chi-square, as z-score", f"{p['chi_z']:.1f}", "-3 to +3", "how even the counts are"),
        ("Index of coincidence", f"{p['ic']:.4f}" if p["ic"] is not None else "n/a",
         f"{core.RANDOM_IC:.4f}", f"letters only (English {core.ENGLISH_IC})"),
        ("Printable bytes", f"{p['printable'] * 100:.0f}%", "about 37%", "share that is ordinary text"),
        ("Distinct byte values", f"{p['unique']}", "-", "out of 256 possible"),
    ]
    for name, mine, random_value, meaning in rows:
        print(f"{name:<26}{mine:>11}{random_value:>13}   {meaning}")
    line()
    print()
    gauge(p["H"])
    label, reasons = core.verdict(p, ref)
    print()
    print(paint("VERDICT: " + label, "bold"))
    for reason in reasons:
        for i, text in enumerate(wrap_lines(reason, WIDTH - 6)):
            print(("  - " if i == 0 else "    ") + text)
    explain(
        "Shannon entropy alone cannot tell a counter, a sorted list and real ciphertext apart: all three can "
        "score close to 8. That is why the verdict also uses other measures.",
        "Min-entropy asks how good the single best guess is. The order check looks at neighbouring bytes, which "
        "Shannon entropy ignores. Chi-square checks whether the counts are as even as chance allows, no more and "
        "no less. The index of coincidence compares letter statistics with English.",
        "Even with all of these, statistics can only say what the data looks like. They cannot prove that "
        "encryption is strong, and they never reveal the message.")
    pause()


# ===========================================================================
# 5. Transform the data and compare entropy
# ===========================================================================
def menu_compare(state):
    title("5. TRANSFORM THE DATA AND COMPARE ENTROPY")
    if need_data(state):
        return
    data = state.data()
    ctx = state.ctx()
    results = core.analyse(data, ctx)
    print(f"Data: {state.label}  ({len(data):,} bytes)")
    print("The same bytes go through every method. Each output is measured the same way.\n")
    print(f"{'#':>2} {'Method':<20}{'Bytes':>7}{'H':>8}{'dH':>8}{'Order':>7}  0 {'':<{BAR - 4}} 8")
    line()
    for i in range(len(results)):
        r = results[i]
        order = core.order_entropy(r["out"])
        print(f"{i:>2} {r['method'].name:<20}{r['n']:>7}{r['H']:>8.3f}{r['dH']:>+8.3f}{order:>7.2f}  {ebar(r['H'])}")
    line()
    print(f"dH = H(output) - H(original). Order = the order check (option 4).")
    print(f"Ceilings: 26 letters {core.LOG2_26:.2f}, Base64 {core.LOG2_65:.2f}, bytes 8.00.")

    caesar = results[1] if len(results) > 1 else None
    best = None
    for r in results[1:]:
        if r["method"].fam == "stream" and (best is None or r["H"] > best["H"]):
            best = r
    reading = []
    if caesar is not None:
        reading.append(f"Caesar and rail fence give exactly the original entropy ({results[0]['H']:.3f}). "
                       "They rename or reorder bytes but keep every count, and entropy only looks at counts.")
    if best is not None:
        reading.append(f"{best['method'].name} pushes entropy to {best['H']:.3f}, close to random data of this "
                       "size. Its output bytes are spread almost evenly over all 256 values.")
    reading.append("Base64 rises but stays below 6.02, because it can only use 65 different symbols. "
                   "Encoding is not encryption.")
    explain(*reading)

    while True:
        raw = ask("\nType a row number for details, or press Enter to go back: ")
        if raw == "":
            return
        if not raw.isdigit() or int(raw) >= len(results):
            print(f"  Please type a number from 0 to {len(results) - 1}.")
            continue
        r = results[int(raw)]
        m = r["method"]
        p = core.profile(r["out"])
        label, reasons = core.verdict(p)
        print()
        line()
        print(paint(m.name, "bold") + f":  H = {r['H']:.4f},  dH = {r['dH']:+.4f},  {r['unique']} distinct values")
        print("What it does   : " + m.describe(ctx))
        print("Verdict        : " + label)
        preview = core.text_preview(r["out"], 120) if m.text else core.hex_preview(r["out"], 32)
        print("First bytes    : " + preview.replace("\n", " "))
        print()
        gauge(r["H"], "this output")
        explain(m.reads)


# ===========================================================================
# 6. Compare the sample collection
# ===========================================================================
def menu_collection(state):
    title("6. COMPARE THE SAMPLE COLLECTION")
    print("A fixed set of plain, transformed and encrypted samples, sorted by entropy.")
    print("Question: can statistics alone tell the kinds of data apart?\n")
    rows = []
    for name, data in core.sample_collection(state.ctx()):
        p = core.profile(data)
        rows.append((p["H"], name, p, core.verdict(p)[0]))
    rows.sort(key=lambda row: row[0])
    print(f"{'Sample':<30}{'Bytes':>6}{'H':>7}{'Order':>7}  0 {'':<{BAR - 10}} 8")
    line()
    for entropy, name, p, label in rows:
        print(f"{name:<30}{p['n']:>6}{entropy:>7.3f}{p['order_H']:>7.2f}  {ebar(entropy, BAR - 6)}")
        print(f"{'':<30}  -> {label}")
    line()
    explain(
        "Entropy alone splits the samples into broad groups: repetitive, text, encoded and random-looking.",
        "It cannot separate plain text from Caesar or rail fence output (identical counts), and it cannot "
        "separate real ciphertext from a counter or sorted bytes (all close to 8).",
        "Adding the order check, chi-square and the index of coincidence separates most of them, as the verdict "
        "lines show. What no statistic can do is tell encrypted data from compressed or random data.")
    pause()


# ===========================================================================
# 7. Sample-size experiment
# ===========================================================================
def menu_size(state):
    title("7. SAMPLE-SIZE EXPERIMENT")
    if need_data(state):
        return
    s = core.size_experiment(state.data(), state.ctx())
    if s["input_len"] < 65536:
        print(f"Your data is {s['input_len']:,} bytes, so it is repeated to fill 65,536 bytes.")
    print("Entropy is measured on the first N bytes of: your data, its RC4 ciphertext,")
    print("and random bytes. A sample of N bytes can never exceed log2(N).\n")
    print(f"{'N bytes':>8}{'Your data':>11}{'RC4':>8}{'Random':>8}{'Ceiling':>9}  RC4: 0 {'':<{BAR - 6}} 8")
    line()
    for i in range(len(s["sizes"])):
        print(f"{s['sizes'][i]:>8,}{s['plain'][i]:>11.3f}{s['cipher'][i]:>8.3f}{s['rand'][i]:>8.3f}"
              f"{s['ceil'][i]:>9.3f}  {ebar(s['cipher'][i])}")
    line()
    explain(
        f"At 256 bytes, encrypted data reads only {s['cipher'][4]:.2f}, not 8. With 256 bytes there is no room "
        "for all 256 values to appear evenly, so small samples always under-report.",
        f"By 65,536 bytes it reaches {s['cipher'][-1]:.3f}. RC4 and truly random data follow the same curve.",
        f"Your data levels off at {s['plain'][-1]:.3f}: once its patterns have been seen, more bytes add "
        "nothing new.",
        "So always compare a sample with random data of the same size, never with the ideal 8.")
    pause()


# ===========================================================================
# 8. Modify the distribution: mix in random bytes
# ===========================================================================
def menu_noise(state):
    title("8. MODIFY THE DISTRIBUTION: MIX IN RANDOM BYTES")
    if need_data(state):
        return
    data = state.data()
    z = core.noise_experiment(data)
    print("A growing share of your bytes is replaced with random values.\n")
    print(f"{'Replaced':>9}{'H':>8}{'Change':>9}{'Distinct':>10}  0 {'':<{BAR - 4}} 8")
    line()
    for pct in range(0, 101, 10):
        print(f"{pct:>8}%{z['H'][pct]:>8.3f}{z['H'][pct] - z['base']:>+9.3f}{z['unique'][pct]:>10}  {ebar(z['H'][pct])}")
    line()
    pct = ask_number("See one step as a byte map. Percent replaced, 0 to 100", 0, 100, 50)
    print(f"\nAt {pct}% replaced: H = {z['H'][pct]:.3f}, {z['unique'][pct]} distinct values\n")
    print_byte_map(z["counts"][pct])
    explain(
        "Each random byte that replaces a text byte takes one count away from a common value and gives it to a "
        "rare one. The distribution flattens, so entropy rises.",
        "In the byte map the dark text clusters fade and the empty cells fill in. At 100% the grid is an even "
        "grey: no value is favoured any more.")
    pause()


# ===========================================================================
# 9. Build a distribution
# ===========================================================================
def menu_shape(state):
    title("9. BUILD A DISTRIBUTION")
    print("Entropy depends on two things: how many symbols are in use, and how evenly")
    print("they are spread. Symbol i gets probability proportional to 1 / i^skew.\n")
    k = ask_number("Symbols in use, k (1 to 256)", 1, 256, 27)
    while True:
        raw = ask("Skew, 0 = perfectly even, 3 = very peaked [1.0]: ", "1.0")
        try:
            skew = float(raw)
        except ValueError:
            print("  Please type a number such as 0, 0.5 or 2.")
            continue
        if 0 <= skew <= 5:
            break
        print("  Please type a number from 0 to 5.")
    d = core.shape_distribution(k, skew)
    print()
    shown = min(16, k)
    for i in range(shown):
        print(f"  symbol {i + 1:>3}  p = {d['p'][i]:.4f}  {bar(d['p'][i], d['p'][0], 40)}")
    if k > shown:
        print(f"  ... and {k - shown} more")
    line()
    share = d["H"] / d["Hmax"] * 100 if d["Hmax"] > 0 else 0.0
    print(f"Entropy            H = {d['H']:.4f} bits")
    print(f"Ceiling      log2({k}) = {d['Hmax']:.4f} bits")
    print(f"Share of ceiling     = {share:.1f}%\n")
    gauge(d["H"], "this distribution")
    print("\nFor comparison, with the same k:")
    for other in (0.0, 1.0, 2.0):
        print(f"  skew {other:.1f}  ->  H = {core.shape_distribution(k, other)['H']:.4f}")
    explain(
        f"With {k} symbols the most entropy possible is log2({k}) = {d['Hmax']:.2f} bits, reached only when every "
        "symbol is equally likely (skew 0).",
        "Skew makes a few symbols common and the rest rare. Entropy falls, even though the same symbols are "
        "still in use. English letters behave like a skew of about 1.")
    pause()


# ===========================================================================
# 10. Limitations
# ===========================================================================
def menu_limits(state):
    title("10. LIMITATIONS OF ENTROPY")
    if need_data(state):
        return
    data = state.data()
    print("Entropy describes the distribution of byte values. It says nothing about")
    print("keys, algorithms or order. Four cases, measured on your current data:\n")
    for card in core.limitations(data, state.ctx()):
        print(" * " + paint(card["h"], "bold"))
        for label, value, note in (card["a"], card["b"]):
            print(f"     {label:<28}{value:>7.3f} bits   {note}")
        for text in wrap_lines(card["p"], WIDTH - 6):
            print("     " + text)
        print()
    line()
    explain(
        "High entropy does not prove secure encryption, and low entropy does not prove the data is unencrypted.",
        "The extra measures in option 4 close some of these gaps: the order check catches sorted and counter "
        "data. None of them can judge the key or the algorithm. That needs cryptanalysis, which is outside this "
        "project.")
    pause()


# ===========================================================================
# 11. Guided demo
# ===========================================================================
def demo_step(number, total, heading):
    print()
    line("=")
    print(" " + paint(f"GUIDED DEMO  -  step {number} of {total}:  {heading}", "bold"))
    line("=")


def demo_next():
    """Return False when the user wants to stop the demo."""
    answer = ask("\nPress Enter for the next step, or type q to stop: ")
    return answer.lower() != "q"


def menu_demo(state):
    ctx = state.ctx()
    total = 9
    text = core.LONG_TEXT.encode("utf-8")

    demo_step(1, total, "What entropy measures")
    print("Take the word HELLO. Count each letter, turn counts into probabilities,")
    print("and add up -p x log2(p):\n")
    print(f"  {'Letter':<8}{'Count':>6}{'p':>7}{'-p log2 p':>11}")
    for value, count, p, part in core.frequency_table(b"HELLO"):
        print(f"  {chr(value):<8}{count:>6}{p:>7.2f}{part:>11.4f}")
    print(f"  {'':<8}{'':>6}{'H =':>7}{core.shannon_entropy(b'HELLO'):>11.4f} bits per letter")
    explain("Entropy measures how unpredictable each symbol is. HELLO scores 1.92 because L repeats; five "
            "different letters would score log2(5) = 2.32.",
            "This project does the same sum over all 256 byte values, so results are in bits per byte, from 0 "
            "(one value repeats forever) to 8 (all values equally likely).")
    if not demo_next():
        return

    p = core.profile(text)
    demo_step(2, total, "Ordinary English")
    print(f"A {len(text):,}-byte English passage: entropy {p['H']:.3f} bits per byte.\n")
    gauge(p["H"], "English")
    print()
    print_byte_map(p["counts"])
    explain("English is predictable: spaces and the letters e, t and a are far more common than q or z. "
            "The byte map shows a few dark clusters and many empty cells.",
            "That unevenness keeps entropy around 4 to 4.5, about half of the 8-bit maximum.")
    if not demo_next():
        return

    cz = core.caesar(text, ctx.shift)
    demo_step(3, total, "Caesar cipher: encrypted, entropy unchanged")
    print("Original : " + core.text_preview(text, 60))
    print("Caesar   : " + core.text_preview(cz, 60) + "\n")
    print(f"Entropy before {core.shannon_entropy(text):.4f}   after {core.shannon_entropy(cz):.4f}")
    explain("The text is unreadable, yet the entropy is identical. Every letter was renamed (e became h, and so on) "
            "but each count stayed the same, and entropy only looks at counts.",
            "So a low entropy reading does not mean data is unencrypted.")
    if not demo_next():
        return

    vg = core.vigenere(text, ctx.vkey)
    ic_before = core.index_of_coincidence(text)[0]
    ic_after = core.index_of_coincidence(vg)[0]
    demo_step(4, total, "Vigenere cipher: slightly flatter")
    print(f"Key: {ctx.vkey}\n")
    print(f"                       Original   Vigenere")
    print(f"Entropy                {core.shannon_entropy(text):>8.3f}   {core.shannon_entropy(vg):>8.3f}")
    print(f"Index of coincidence   {ic_before:>8.4f}   {ic_after:>8.4f}   (English {core.ENGLISH_IC}, random {core.RANDOM_IC:.4f})")
    explain("Vigenere shifts each letter by a different amount, so one plaintext letter turns into several "
            "ciphertext letters. The letter counts flatten and entropy rises a little.",
            "The index of coincidence shows it more clearly: it drops from the English value towards the value for "
            "random letters. It is still only letters, so it can never pass 4.70 bits.")
    if not demo_next():
        return

    rc = core.rc4(text, ctx.pass_bytes)
    p = core.profile(rc)
    demo_step(5, total, "RC4 stream cipher: looks random")
    print(f"Entropy {p['H']:.3f} bits per byte, {p['unique']} of 256 values used.\n")
    gauge(p["H"], "RC4")
    print()
    print_byte_map(p["counts"])
    explain("RC4 mixes every byte with a keystream. The output uses almost every byte value about equally often, "
            "so the byte map turns an even grey and entropy jumps close to 8.",
            "This is what well-encrypted data looks like statistically: no favourite values for an analyst "
            "to count.")
    if not demo_next():
        return

    s = core.size_experiment(text, ctx)
    demo_step(6, total, "Sample size changes the reading")
    for i in (0, 4, 6, 12):
        print(f"  RC4 output, first {s['sizes'][i]:>6,} bytes:  {s['cipher'][i]:.3f}  {ebar(s['cipher'][i])}")
    explain("The same encrypted stream reads 4.0 at 16 bytes and almost 8.0 at 65,536 bytes. A small sample "
            "cannot contain all 256 values evenly.",
            "So the program compares every sample with random data of the same size, not with the ideal 8.")
    if not demo_next():
        return

    counter = core.counter_bytes(len(text))
    p = core.profile(counter)
    label, reasons = core.verdict(p)
    demo_step(7, total, "A high number can lie")
    print("The bytes 00 01 02 03 ... FF 00 01 ... in order. No key, no secret.\n")
    print(f"  Shannon entropy  {p['H']:.3f}   (as high as encryption)")
    print(f"  Order check      {p['order_H']:.3f}   (each byte is the previous one plus 1)\n")
    print(paint("VERDICT: " + label, "bold"))
    explain("Every value appears equally often, so Shannon entropy gives it nearly a perfect 8. It is completely "
            "predictable.",
            "The order check measures the steps between neighbouring bytes. Here every step is +1, so it scores 0 "
            "and exposes the pattern. One number is never enough.")
    if not demo_next():
        return

    mixed = core.mixed_file(ctx)
    windows = core.entropy_map(mixed, 256)
    demo_step(8, total, "Finding encrypted data inside a file")
    print(f"A {len(mixed):,}-byte file. Whole-file entropy: {core.shannon_entropy(mixed):.2f}, which says little.\n")
    strip = ""
    for start, length, h in windows:
        strip += paint(SHADES[min(9, int(h / 8 * 9.99))], zone_style(h))
    print("Entropy map, left to right:  [" + strip + "]")
    for start, end in core.high_entropy_regions(windows):
        print(f"High-entropy region: bytes {start:,} to {end:,}")
    explain("Measured window by window, the file shows text, then a block of random-looking bytes, then text "
            "again. The map points straight at the encrypted section.",
            "Investigators use this to spot hidden or encrypted parts of disk images, documents and malware.")
    if not demo_next():
        return

    demo_step(9, total, "What we conclude")
    step_box([
        "1. Entropy measures how evenly byte values are spread, from 0 to 8 bits.",
        "2. Text sits around 4 to 5. Good encryption sits close to 8.",
        "3. Substitution and transposition can hide a message without changing entropy.",
        "4. Small samples read low, so compare with random data of the same size.",
        "5. High entropy can come from encryption, compression, random data or a pattern.",
        "6. Extra measures (order check, chi-square, index of coincidence) separate more cases.",
        "7. No statistic proves encryption is strong. Entropy is a first look, not a verdict.",
    ])
    explain("That is the whole project in one run. Every number above came from the same hand-written functions "
            "the rest of the menu uses.")
    pause()


# ===========================================================================
# 12. Glossary
# ===========================================================================
GLOSSARY = [
    ("Bit", "The smallest unit of information: one yes-or-no answer."),
    ("Byte", "8 bits. It can hold one of 256 values, 0 to 255 (00 to FF in hex)."),
    ("Frequency", "How many times a value appears in the data."),
    ("Probability, p", "Frequency divided by the total number of bytes."),
    ("Shannon entropy, H", "H = -sum p log2 p. Average unpredictability, in bits per byte: 0 to 8."),
    ("Ceiling", "The most entropy possible: log2 of the number of possible symbols. 8 for bytes, 4.70 for "
                "26 letters, 6.02 for Base64."),
    ("dH", "Change in entropy: H(output) minus H(original)."),
    ("Min-entropy", "-log2 of the highest probability. Worst-case unpredictability; used in security standards."),
    ("Order check", "Entropy of the steps between neighbouring bytes. Low when each byte predicts the next."),
    ("Chi-square", "How far the counts are from perfectly even. Shown as a z-score: random data is -3 to +3."),
    ("Index of coincidence", "Chance that two random letters from the text match. English 0.067, random 0.038."),
    ("Plaintext", "The original readable data."),
    ("Ciphertext", "Data after encryption."),
    ("Key", "The secret value an encryption method uses."),
    ("Substitution cipher", "Replaces each symbol with another (Caesar, Vigenere)."),
    ("Transposition cipher", "Keeps the symbols but changes their order (rail fence)."),
    ("Stream cipher", "Mixes each byte with a keystream using XOR (one-time pad, RC4)."),
    ("Encoding", "A reversible change of format with no key, such as Base64. Not encryption."),
    ("Sample size", "Number of bytes measured. Small samples read lower than the true entropy."),
    ("Entropy map", "Entropy measured window by window along the data, to find high-entropy regions."),
    ("Verdict", "This program's reading of what kind of data a sample looks like, with reasons."),
]


def menu_glossary(state):
    title("12. GLOSSARY")
    for term, meaning in GLOSSARY:
        lines = wrap_lines(meaning, WIDTH - 26)
        print(f"  {paint(term.ljust(22), 'bold')}{lines[0]}")
        for text in lines[1:]:
            print(" " * 24 + text)
    pause()


# ===========================================================================
# 13. Settings
# ===========================================================================
def menu_settings(state):
    while True:
        title("13. SETTINGS")
        print(f"  1. Caesar shift            : {state.shift}")
        print(f"  2. Vigenere key            : {state.ctx().vkey}")
        print(f"  3. Passphrase (XOR, RC4)   : {state.passphrase}")
        print(f"  4. Count symbols from      : {'letters only, A-Z' if state.mode == 'az' else 'every byte'}")
        print(f"  5. Colour                  : {'on' if Colour.on else 'off'}")
        print("  0. Back")
        choice = ask("\nChoose: ")
        if choice == "1":
            state.shift = ask_number("Shift, 1 to 25", 1, 25, state.shift)
        elif choice == "2":
            state.vkey = ask("New key (letters only): ", state.vkey)
        elif choice == "3":
            state.passphrase = ask("New passphrase: ", state.passphrase)
        elif choice == "4":
            state.mode = "raw" if state.mode == "az" else "az"
        elif choice == "5":
            Colour.on = not Colour.on
            if Colour.on and os.name == "nt":
                os.system("")
        elif choice in ("0", ""):
            return
        else:
            print("  Please choose 0 to 5.")


# ===========================================================================
# 14. Optional visual dashboard
# ===========================================================================
def menu_dashboard(state):
    title("14. VISUAL DASHBOARD (OPTIONAL)")
    try:
        import app                               # needs Flask; not used by anything else
    except ImportError:
        print("The dashboard needs Flask, which is not installed.")
        print("Install it with:  pip install flask")
        print("Everything else in this menu works without it.")
        pause()
        return
    print("Opening http://127.0.0.1:5000 in your browser.")
    print("Press Ctrl+C here to close the dashboard and return to the menu.")
    try:
        app.start()
    except KeyboardInterrupt:
        pass
    except (SystemExit, OSError):
        print("\nIf the dashboard never opened, port 5000 may be in use by another program.")
    print("\nDashboard closed.")
    pause()


# ===========================================================================
# Main menu
# ===========================================================================
MENU = [
    ("DATA", [
        ("1", "Load data (type text, open a file, or pick a sample)", menu_load)]),
    ("LOOK AT THE DATA", [
        ("2", "Byte frequencies and entropy, step by step", menu_frequency),
        ("3", "Entropy map: where in the data is it random?", menu_entropy_map),
        ("4", "Full statistical profile and verdict", menu_profile)]),
    ("EXPERIMENTS", [
        ("5", "Transform the data and compare entropy", menu_compare),
        ("6", "Compare the sample collection", menu_collection),
        ("7", "Sample-size experiment", menu_size),
        ("8", "Modify the distribution (mix in random bytes)", menu_noise),
        ("9", "Build a distribution (symbols and skew)", menu_shape)]),
    ("UNDERSTAND", [
        ("10", "Limitations of entropy", menu_limits),
        ("11", "Guided demo: the whole project, step by step", menu_demo),
        ("12", "Glossary", menu_glossary)]),
    ("OTHER", [
        ("13", "Settings (keys, preprocessing, colour)", menu_settings),
        ("14", "Open the visual dashboard (optional)", menu_dashboard)]),
]


def main():
    Colour.on = colour_supported()
    state = State()
    while True:
        p = core.profile(state.data())
        title("ENTROPY LAB   P6: Entropy-Based Analysis of Encrypted Data")
        print(f" Current data : {state.label}")
        print(f" Size         : {p['n']:,} bytes, {p['unique']} distinct byte values")
        entropy_text = paint(format(p["H"], ".3f"), zone_style(p["H"]))
        print(f" Entropy      : {entropy_text} bits per byte   {ebar(p['H'], 24)}")
        print(f" Looks like   : {core.verdict(p)[0]}")
        line()
        actions = {}
        for group, items in MENU:
            print(" " + paint(group, "dim"))
            for key, text, action in items:
                print(f"  {key:>2}. {text}")
                actions[key] = action
        print("   0. Exit")
        line()
        print(" New here? Start with 11, the guided demo.")
        choice = ask("Choose an option: ")
        if choice == "0":
            print("Goodbye.")
            return
        if choice in actions:
            actions[choice](state)
        else:
            print("That is not on the menu. Please type a number from 0 to 14.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nGoodbye.")
