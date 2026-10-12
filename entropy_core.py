"""
entropy_core.py
===============
P6: Entropy-Based Analysis of Encrypted Data.

This file holds all the maths. The subject is the statistical distribution of
the data and its entropy. The ciphers are only there to produce different
kinds of samples to measure.

Everything is written by hand:
  - no cryptography library
  - no ready-made frequency counter
  - no ready-made Base64, hashing or random-number functions
The only import is `math`, used for log2().

Entropy is always measured over byte values, in bits per byte:
  0 = one value repeats, 8 = all 256 byte values equally likely.
"""

import math

MAX_BYTES = 200_000              # longer inputs are cut to this many bytes
LOG2_26 = math.log2(26)          # entropy ceiling for 26 letters, about 4.70
LOG2_65 = math.log2(65)          # entropy ceiling for Base64 text (64 characters and "="), about 6.02


# ===========================================================================
# 1. FREQUENCY, PROBABILITY AND ENTROPY
# ===========================================================================
def count_bytes(data):
    """Step 1: how many times does each of the 256 byte values appear?"""
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return counts


def count_distinct(counts):
    """How many different byte values appear at least once."""
    distinct = 0
    for count in counts:
        if count > 0:
            distinct += 1
    return distinct


def entropy_from_counts(counts, total):
    """
    Steps 2 and 3: turn each count into a probability, then apply
    Shannon's formula  H = - sum( p * log2(p) ).
    """
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count > 0:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def shannon_entropy(data):
    """Entropy of a byte string, in bits per byte."""
    return entropy_from_counts(count_bytes(data), len(data))


def measure(data):
    """Everything we report about one sample."""
    counts = count_bytes(data)
    total = len(data)
    return {
        "counts": counts,
        "n": total,
        "unique": count_distinct(counts),
        "H": entropy_from_counts(counts, total),
    }


def frequency_table(data):
    """
    One row per byte value that appears: (value, count, probability,
    contribution to entropy). Most frequent first.
    """
    counts = count_bytes(data)
    total = len(data)
    rows = []
    for value in range(256):
        count = counts[value]
        if count > 0:
            probability = count / total
            rows.append((value, count, probability, -probability * math.log2(probability)))
    rows.sort(key=lambda row: row[1], reverse=True)
    return rows


def classify(entropy, total):
    """
    Put a sample into a band by its entropy alone. This is the "can entropy
    tell samples apart?" test, and it is deliberately simple.
    """
    if total < 100:
        return "Too few bytes to judge"
    if entropy < 2.0:
        return "Highly repetitive"
    if entropy < 5.5:
        return "Structured, text-like"
    if entropy < 6.5:
        return "Encoded or partly mixed"
    return "High entropy: encrypted, compressed or random"


# ===========================================================================
# 2. A SMALL RANDOM-NUMBER GENERATOR (xorshift, 32-bit)
#    Used for the one-time-pad key, the random reference sample and the
#    noise experiment. Seeded, so every run gives the same results.
#    It is NOT cryptographically secure. It only needs to look uniform.
# ===========================================================================
class XorShift:
    def __init__(self, seed):
        self.state = (seed & 0xFFFFFFFF) or 0x9E3779B9      # state must not be 0

    def next_u32(self):
        x = self.state
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        self.state = x
        return x

    def next_byte(self):
        return (self.next_u32() >> 24) & 0xFF               # use the top 8 bits

    def below(self, limit):
        """A whole number from 0 to limit - 1."""
        return self.next_u32() % limit


def random_bytes(seed, length):
    """`length` pseudo-random bytes from the generator above."""
    rng = XorShift(seed)
    out = bytearray(length)
    for i in range(length):
        out[i] = rng.next_byte()
    return bytes(out)


def simple_hash(data):
    """Turn a passphrase into a 32-bit seed (FNV-1a). Not a security feature."""
    h = 2166136261
    for byte in data:
        h ^= byte
        h = (h * 16777619) & 0xFFFFFFFF
    return h


# ===========================================================================
# 3. TRANSFORMATIONS
#    Each one takes bytes and returns bytes.
# ===========================================================================
def caesar(data, shift):
    """Substitution: shift every letter by the same amount."""
    shift %= 26
    out = bytearray(len(data))
    for i in range(len(data)):
        v = data[i]
        if 65 <= v <= 90:                       # A-Z
            out[i] = (v - 65 + shift) % 26 + 65
        elif 97 <= v <= 122:                    # a-z
            out[i] = (v - 97 + shift) % 26 + 97
        else:
            out[i] = v                          # everything else is unchanged
    return bytes(out)


def vigenere(data, key):
    """Substitution: shift each letter by an amount set by the repeating key."""
    out = bytearray(len(data))
    j = 0                                       # position in the key
    for i in range(len(data)):
        v = data[i]
        shift = ord(key[j % len(key)]) - 65
        if 65 <= v <= 90:
            out[i] = (v - 65 + shift) % 26 + 65
            j += 1
        elif 97 <= v <= 122:
            out[i] = (v - 97 + shift) % 26 + 97
            j += 1
        else:
            out[i] = v
    return bytes(out)


def rail_fence(data, rails=3):
    """Transposition: write the bytes in a zigzag, read them off row by row."""
    if rails < 2 or len(data) < 3:
        return bytes(data)
    rows = []
    for _ in range(rails):
        rows.append(bytearray())
    row = 0
    step = 1
    for v in data:
        rows[row].append(v)
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    out = bytearray()
    for r in rows:
        out += r
    return bytes(out)


def xor_repeating(data, key):
    """XOR each byte with a short key that repeats."""
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ key[i % len(key)]
    return bytes(out)


def one_time_pad(data, seed):
    """
    XOR each byte with a fresh key byte, one key byte per data byte.
    A real one-time pad needs a truly random key. Here the key comes from the
    seeded generator so the experiment repeats.
    """
    rng = XorShift(seed)
    out = bytearray(len(data))
    for i in range(len(data)):
        out[i] = data[i] ^ rng.next_byte()
    return bytes(out)


def rc4(data, key):
    """RC4 stream cipher: build a shuffled table from the key, then XOR a keystream."""
    s = list(range(256))
    j = 0
    for i in range(256):                                    # key scheduling
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for n in range(len(data)):                              # keystream generation
        i = (i + 1) & 255
        j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out[n] = data[n] ^ s[(s[i] + s[j]) & 255]
    return bytes(out)


_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def base64_encode(data):
    """
    Encoding, not encryption: every 3 bytes become 4 printable characters.
    If the last group is short, "=" pads it, so 65 different symbols can appear.
    """
    out = bytearray()
    for i in range(0, len(data), 3):
        chunk = data[i:i + 3]
        number = 0
        for byte in chunk:
            number = (number << 8) | byte
        number <<= 8 * (3 - len(chunk))                     # pad the last group with zero bits
        for position in range(4):
            if position <= len(chunk):
                out.append(ord(_B64[(number >> (18 - 6 * position)) & 63]))
            else:
                out.append(ord("="))
    return bytes(out)


# ===========================================================================
# 4. SETTINGS FOR ONE RUN
# ===========================================================================
class Context:
    """The keys every transformation uses. Built from the user's settings."""

    def __init__(self, shift=3, vkey="SECURE", passphrase="entropy-lab-demo"):
        self.shift = int(shift) % 26
        letters = ""
        for ch in vkey.upper():
            if "A" <= ch <= "Z":
                letters += ch
        self.vkey = letters or "KEY"
        self.pass_bytes = (passphrase or "entropy").encode("utf-8")[:256]
        self.seed = simple_hash(self.pass_bytes)


class Method:
    def __init__(self, id, name, fam, run, how, reads, text=False):
        self.id = id            # short name used in code
        self.name = name        # name shown to the user
        self.fam = fam          # classical | stream | transform
        self.run = run          # function(plain, ctx) -> bytes
        self.how = how          # what the method does (text, or function of ctx)
        self.reads = reads      # what the entropy reading shows
        self.text = text        # True if the output is printable text

    def describe(self, ctx):
        return self.how(ctx) if callable(self.how) else self.how


PLAIN = Method(
    "plain", "Original data", "plain", lambda p, c: p,
    "Your input, exactly as the methods receive it.",
    "The baseline. Every other row is compared against this number.", text=True,
)

METHODS = [
    Method("caesar", "Caesar", "classical", lambda p, c: caesar(p, c.shift),
           lambda c: f"Shifts every letter {c.shift} places along the alphabet.",
           "Each letter is only renamed, so the frequency pattern survives intact. Entropy cannot change.", text=True),
    Method("vigenere", "Vigenere", "classical", lambda p, c: vigenere(p, c.vkey),
           lambda c: f"Shifts each letter by a different amount, set by the repeating key {c.vkey}.",
           "One plaintext letter now maps to several ciphertext letters, which flattens the frequencies. "
           "The output is still only letters, so 4.70 bits is the ceiling.", text=True),
    Method("rail", "Rail fence", "classical", lambda p, c: rail_fence(p, 3),
           "Writes the bytes in a three-row zigzag and reads them off row by row. Nothing is substituted.",
           "Same bytes in a new order. Entropy counts symbols and ignores their order, so the reading is identical.", text=True),
    Method("xor", "XOR, repeating key", "stream", lambda p, c: xor_repeating(p, c.pass_bytes),
           lambda c: f"XORs each byte with a {len(c.pass_bytes)}-byte key that repeats.",
           "Entropy climbs, yet the repeating key leaves a pattern in the output. A higher reading here is not safety."),
    Method("otp", "One-time pad", "stream", lambda p, c: one_time_pad(p, c.seed),
           "XORs each byte with a fresh key byte from a seeded generator, one key byte per data byte.",
           "The output is statistically uniform. Any shortfall from 8 bits comes from the sample being small."),
    Method("rc4", "RC4", "stream", lambda p, c: rc4(p, c.pass_bytes),
           "A stream cipher from 1987, written here by hand. It builds a keystream and XORs it into the data.",
           "It reads as high as random data, yet RC4 is considered broken. Entropy cannot see that."),
    Method("b64", "Base64", "transform", lambda p, c: base64_encode(p),
           "Re-encodes the bytes as 64 printable characters, plus = as padding at the end. No key and no secrecy.",
           "This is not encryption. Only 65 symbols are possible (64 characters and the = padding sign), "
           "so the reading can never pass log2(65), about 6.02 bits.", text=True),
    Method("rand", "Random reference", "transform", lambda p, c: random_bytes(c.seed ^ 0x5EED, len(p)),
           "Pseudo-random bytes, the same length as the input. It contains no message at all.",
           "The reference for what uniform data looks like at this sample size."),
]


# ===========================================================================
# 5. THE EXPERIMENTS
# ===========================================================================
def preprocess(data, mode="raw"):
    """'raw' keeps every byte. 'az' keeps letters only and makes them uppercase."""
    data = data[:MAX_BYTES]
    if mode != "az":
        return bytes(data)
    out = bytearray()
    for v in data:
        if 65 <= v <= 90:
            out.append(v)
        elif 97 <= v <= 122:
            out.append(v - 32)
    return bytes(out)


def analyse(plain, ctx, enabled=None):
    """Same input, every method, one measurement each. Returns a list of results."""
    base = measure(plain)
    first = {"method": PLAIN, "out": plain, "dH": 0.0}
    first.update(base)
    results = [first]
    if len(plain) == 0:
        return results
    for m in METHODS:
        if enabled is not None and m.id not in enabled:
            continue
        out = m.run(plain, ctx)
        r = {"method": m, "out": out}
        r.update(measure(out))
        r["dH"] = r["H"] - base["H"]            # change in entropy
        results.append(r)
    return results


SIZES = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]


def size_experiment(plain, ctx):
    """How the measured entropy changes with sample size, from 16 to 65,536 bytes."""
    largest = SIZES[-1]
    tiled = bytearray(largest)                  # repeat a short input to fill 65,536 bytes
    for i in range(largest):
        tiled[i] = plain[i % len(plain)]
    tiled = bytes(tiled)
    cipher = rc4(tiled, ctx.pass_bytes)
    rand = random_bytes(ctx.seed ^ 0x5EED, largest)

    def curve(data):
        counts = [0] * 256
        done = 0
        out = []
        for n in SIZES:
            while done < n:                     # count only the newly added bytes
                counts[data[done]] += 1
                done += 1
            out.append(entropy_from_counts(counts, n))
        return out

    ceiling = []
    for n in SIZES:                             # N bytes hold at most N values: H <= log2(N)
        ceiling.append(min(8.0, math.log2(n)))
    return {"sizes": SIZES, "plain": curve(tiled), "cipher": curve(cipher), "rand": curve(rand),
            "ceil": ceiling, "input_len": len(plain)}


def noise_experiment(plain):
    """Replace 0% to 100% of the bytes with random ones and re-measure after each step."""
    n = len(plain)
    rng = XorShift(0xC0FFEE)
    noise = bytearray(n)
    for i in range(n):
        noise[i] = rng.next_byte()
    order = list(range(n))                      # the order in which bytes get replaced
    for i in range(n - 1, 0, -1):               # Fisher-Yates shuffle
        j = rng.below(i + 1)
        order[i], order[j] = order[j], order[i]

    counts = count_bytes(plain)
    all_counts, entropies, uniques = [], [], []
    done = 0
    for pct in range(101):
        cut = (n * pct + 50) // 100             # how many bytes are replaced at this step
        while done < cut:
            i = order[done]
            counts[plain[i]] -= 1
            counts[noise[i]] += 1
            done += 1
        all_counts.append(list(counts))
        entropies.append(entropy_from_counts(counts, n))
        uniques.append(count_distinct(counts))
    return {"base": entropies[0], "H": entropies, "unique": uniques, "counts": all_counts}


def shape_distribution(k, skew):
    """A k-symbol distribution with p(i) proportional to 1 / i**skew. skew 0 is uniform."""
    k = max(1, min(256, int(k)))
    weights = []
    total = 0.0
    for i in range(1, k + 1):
        w = 1 / (i ** skew)
        weights.append(w)
        total += w
    p = []
    entropy = 0.0
    for w in weights:
        probability = w / total
        p.append(probability)
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return {"k": k, "skew": skew, "p": p, "H": entropy, "Hmax": math.log2(k)}


def sort_bytes(data):
    """Rebuild the data in sorted order straight from its frequency table."""
    counts = count_bytes(data)
    out = bytearray()
    for value in range(256):
        for _ in range(counts[value]):
            out.append(value)
    return bytes(out)


def counter_bytes(length):
    """00 01 02 ... FF 00 01 ... : completely predictable, no secret, no randomness."""
    out = bytearray(length)
    for i in range(length):
        out[i] = i % 256
    return bytes(out)


def limitations(plain, ctx):
    """Four cases, measured on the current input, where entropy alone misleads."""
    base = shannon_entropy(plain)
    cz = shannon_entropy(caesar(plain, ctx.shift or 3))
    cipher = rc4(plain, ctx.pass_bytes)
    counter = counter_bytes(len(plain))
    ordered = sort_bytes(cipher)
    return [
        {"h": "Encrypted, and the number does not move.",
         "p": "A Caesar cipher hides the message from a casual reader, yet it only renames letters. "
              "Entropy stays put, so a low reading does not mean \"not encrypted\".",
         "a": ["Original data", base, "baseline"],
         "b": ["Caesar ciphertext", cz, f"dH = {cz - base:+.3f}"]},
        {"h": "High entropy, and nothing is secret.",
         "p": "The bytes 00 01 02 ... FF repeated are completely predictable. They hold no message and use "
              "no key, yet every value appears equally often, so they read as high as real ciphertext.",
         "a": ["Counter 00 01 02 ...", shannon_entropy(counter), "no key, no secret"],
         "b": ["RC4 ciphertext", shannon_entropy(cipher), f"{len(cipher):,} bytes"]},
        {"h": "Sort the ciphertext and the score is identical.",
         "p": "Sorted bytes are a predictable staircase, with every pattern exposed. Entropy only counts "
              "how often each value appears, so it cannot see order or structure.",
         "a": ["RC4 ciphertext", shannon_entropy(cipher), hex_preview(cipher, 14)],
         "b": ["Same bytes, sorted", shannon_entropy(ordered), hex_preview(ordered, 14)]},
        {"h": "Same data, different number.",
         "p": "Written as Base64, the data can only use 64 characters and the = padding sign, so the reading "
              "drops to about 6 bits. "
              "Always measure the raw bytes, and say which symbols you counted.",
         "a": ["RC4 ciphertext, raw bytes", shannon_entropy(cipher), "ceiling 8.00"],
         "b": ["The same, as Base64", shannon_entropy(base64_encode(cipher)), f"ceiling {LOG2_65:.2f}"]},
    ]


# ===========================================================================
# 6. BEYOND SHANNON ENTROPY
#    Shannon entropy only looks at how often each value appears. These extra
#    statistics look at the data from other angles. Each is a short formula
#    written out by hand.
# ===========================================================================
ENGLISH_IC = 0.0667              # index of coincidence of ordinary English letters
RANDOM_IC = 1 / 26               # index of coincidence of random letters, about 0.0385


def min_entropy(counts, total):
    """
    Worst-case unpredictability: -log2(probability of the most common value).
    Shannon entropy is the average case; this is how easy the single best
    guess is. It is always less than or equal to Shannon entropy.
    """
    if total == 0:
        return 0.0
    highest = 0
    for count in counts:
        if count > highest:
            highest = count
    return max(0.0, -math.log2(highest / total))      # max() turns -0.0 into 0.0


def difference_bytes(data):
    """d[i] = (x[i+1] - x[i]) mod 256: the step from each byte to the next one."""
    out = bytearray(max(0, len(data) - 1))
    for i in range(len(data) - 1):
        out[i] = (data[i + 1] - data[i]) & 255
    return bytes(out)


def order_entropy(data):
    """
    The order check. Entropy of the steps between neighbouring bytes.
    Shannon entropy ignores order; this does not. If each byte can be
    predicted from the one before (sorted data, a counter), the steps repeat
    and this number falls far below the normal entropy.
    """
    return shannon_entropy(difference_bytes(data))


def chi_square(counts, total):
    """
    How far the counts are from perfectly even.
    chi2 = sum( (observed - expected)^2 / expected ), expected = N / 256.
    """
    if total == 0:
        return 0.0
    expected = total / 256
    chi = 0.0
    for count in counts:
        chi += (count - expected) ** 2 / expected
    return chi


def chi_square_z(chi, freedom=255):
    """
    Turn chi-square into a z-score (Wilson-Hilferty approximation).
    Random data lands between about -3 and +3.
    Far above +3: too uneven to be random. Far below -3: too even to be random.
    """
    a = 2 / (9 * freedom)
    return ((chi / freedom) ** (1 / 3) - (1 - a)) / (a ** 0.5)


def index_of_coincidence(data):
    """
    Chance that two letters picked at random from the text are the same letter.
    IC = sum( f * (f - 1) ) / ( N * (N - 1) ), over the 26 letters only.
    English is about 0.067, random letters about 0.038. A one-shift cipher
    (Caesar) keeps the value; a multi-shift cipher (Vigenere) lowers it.
    Returns (ic, number_of_letters); ic is None when there are under 2 letters.
    """
    counts = [0] * 26
    letters = 0
    for v in data:
        if 65 <= v <= 90:
            counts[v - 65] += 1
            letters += 1
        elif 97 <= v <= 122:
            counts[v - 97] += 1
            letters += 1
    if letters < 2:
        return None, letters
    same = 0
    for f in counts:
        same += f * (f - 1)
    return same / (letters * (letters - 1)), letters


def printable_share(data):
    """Share of bytes that are ordinary printable text (letters, digits, punctuation, spaces)."""
    if len(data) == 0:
        return 0.0
    printable = 0
    for v in data:
        if 32 <= v <= 126 or v in (9, 10, 13):
            printable += 1
    return printable / len(data)


_B64_BYTES = _B64 + "="


def uses_base64_alphabet(data):
    """
    True when the data looks like Base64: every byte is one of the 64 Base64
    characters or '=', the length is a multiple of 4, and both upper- and
    lower-case letters appear (so plain capital letters do not count).
    """
    if len(data) < 16 or len(data) % 4 != 0:
        return False
    upper = lower = False
    for v in data:
        if chr(v) not in _B64_BYTES:
            return False
        if 65 <= v <= 90:
            upper = True
        elif 97 <= v <= 122:
            lower = True
    return upper and lower


def profile(data):
    """Every statistic for one sample, in one place."""
    counts = count_bytes(data)
    total = len(data)
    ic, letters = index_of_coincidence(data)
    chi = chi_square(counts, total)
    return {
        "n": total,
        "counts": counts,
        "unique": count_distinct(counts),
        "H": entropy_from_counts(counts, total),
        "min_H": min_entropy(counts, total),
        "order_H": order_entropy(data),
        "chi": chi,
        "chi_z": chi_square_z(chi) if total else 0.0,
        "ic": ic,
        "letters": letters,
        "printable": printable_share(data),
        "base64": uses_base64_alphabet(data),
        "regions": high_entropy_regions(entropy_map(data)) if total >= 1024 else [],
    }


_REFERENCE_CACHE = {}


def random_reference(total):
    """
    What truly random-looking data of the SAME size scores on each statistic.
    Small samples score lower than 8 even when random, so every verdict
    compares against this, not against the ideal 8.0.
    """
    if total in _REFERENCE_CACHE:
        return _REFERENCE_CACHE[total]
    runs = 3 if total < 4096 else 1
    sums = {"H": 0.0, "min_H": 0.0, "order_H": 0.0, "chi_z": 0.0}
    for run in range(runs):
        p = profile(random_bytes(0xACE + run * 7919, total))
        for key in sums:
            sums[key] += p[key]
    result = {}
    for key in sums:
        result[key] = sums[key] / runs
    _REFERENCE_CACHE[total] = result
    return result


def verdict(p, ref=None):
    """
    Combine several statistics into one reading, with the reasons behind it.
    This answers the brief's question: can samples be told apart from their
    statistics alone? Returns (label, list_of_reasons).
    """
    n = p["n"]
    if n < 64:
        return "Too little data to judge", [
            f"There are only {n} bytes. Below about 64 bytes every statistic is unreliable."]
    if ref is None:
        ref = random_reference(n)
    H = p["H"]
    if H < 1.0:
        return "Almost constant", [
            f"Entropy is only {H:.2f} bits per byte: one or two values fill almost the whole sample."]

    if H >= ref["H"] - 0.25:                                   # as high as random data of this size
        if p["order_H"] < 0.6 * H:
            return "High entropy, but in a predictable order", [
                f"Values are spread evenly: entropy {H:.2f}, close to random data of this size ({ref['H']:.2f}).",
                f"But the steps between neighbouring bytes repeat: order check {p['order_H']:.2f}, far below {H:.2f}.",
                "This is a counter, sorted data or another pattern. It is not encryption."]
        if p["chi_z"] < -4:
            return "Too even to be random", [
                f"Entropy {H:.2f} is as high as random data, but chi-square z = {p['chi_z']:.1f}.",
                "Random data is never this perfectly even. Something generated these values in a pattern."]
        reasons = [
            f"Entropy {H:.2f} matches random data of the same size ({ref['H']:.2f}).",
            f"No neighbour pattern: order check {p['order_H']:.2f} is as high as the entropy.",
        ]
        if n >= 1280:
            reasons.append(f"Chi-square z = {p['chi_z']:.1f}, inside the random range of -3 to +3."
                           if -3 <= p["chi_z"] <= 3 else
                           f"Chi-square z = {p['chi_z']:.1f}, slightly outside -3 to +3.")
        reasons.append("Statistics cannot say whether it is encrypted, compressed or simply random.")
        return "Looks random: encrypted, compressed or random data", reasons

    covered = 0
    for start, end in p["regions"]:
        covered += end - start
    if p["regions"] and 0.05 * n <= covered <= 0.9 * n:
        reasons = [f"Overall entropy {H:.2f} is below random data, but it is not the same all the way through."]
        for start, end in p["regions"]:
            reasons.append(f"Bytes {start:,} to {end:,} have random-looking entropy ({(end - start) / n * 100:.0f}% of the data).")
        reasons.append("The rest is lower. Use the entropy map to see the regions.")
        return "Mixed: contains a high-entropy block", reasons

    if p["base64"]:
        reasons = [
            "Every byte is one of the 64 Base64 characters or '='.",
            f"Entropy {H:.2f}, against a ceiling of {LOG2_65:.2f} for this alphabet.",
            "Encoding is not encryption: anyone can reverse it without a key."]
        if H >= 5.75:
            reasons.append("The value is near the ceiling, so the hidden bytes probably look random themselves.")
        return "Encoded text (Base64)", reasons

    if p["printable"] >= 0.95:
        ic = p["ic"]
        if ic is not None and p["letters"] >= 50:
            if ic >= 0.055:
                return "Readable text, or a simple substitution of it", [
                    f"{p['printable'] * 100:.0f}% of bytes are printable text.",
                    f"Index of coincidence {ic:.4f}, close to English ({ENGLISH_IC}).",
                    "A Caesar cipher keeps these statistics, so it cannot be told apart from plain text this way."]
            if ic <= 0.050:
                return "Text with flattened letter statistics", [
                    f"{p['printable'] * 100:.0f}% of bytes are printable text.",
                    f"Index of coincidence {ic:.4f}: well below English ({ENGLISH_IC}), towards random letters ({RANDOM_IC:.4f}).",
                    "This is typical of a multi-shift cipher such as Vigenere."]
        return "Text-like data", [
            f"{p['printable'] * 100:.0f}% of bytes are printable text.",
            f"Entropy {H:.2f} sits in the usual range for text, well below random ({ref['H']:.2f})."]

    return "Structured binary data", [
        f"Only {p['printable'] * 100:.0f}% of bytes are printable, so this is not plain text.",
        f"Entropy {H:.2f} is well below random data of this size ({ref['H']:.2f}): patterns remain.",
        "Typical of weak scrambling such as a repeating-key XOR, or of program and file-format data."]


def entropy_map(data, window=256, columns=64):
    """
    Entropy measured window by window along the data.
    Returns a list of (start, length, entropy). Long data gets wider windows so
    there are never more than `columns` of them.
    """
    n = len(data)
    if n == 0:
        return []
    size = max(window, -(-n // columns))                   # -(-a // b) rounds a / b up
    windows = []
    for start in range(0, n, size):
        chunk = data[start:start + size]
        if len(chunk) < size // 2 and windows:             # fold a short tail into the window before it
            prev = windows[-1][0]
            chunk = data[prev:n]
            windows[-1] = (prev, len(chunk), shannon_entropy(chunk))
            break
        windows.append((start, len(chunk), shannon_entropy(chunk)))
    return windows


def high_entropy_regions(windows, threshold=6.3):
    """Join neighbouring high-entropy windows into regions: list of (start, end)."""
    regions = []
    current = None
    for start, length, entropy in windows:
        if entropy >= threshold:
            if current is None:
                current = [start, start + length]
            else:
                current[1] = start + length
        elif current is not None:
            regions.append((current[0], current[1]))
            current = None
    if current is not None:
        regions.append((current[0], current[1]))
    return regions


def byte_map(counts):
    """
    The 256 byte values as a 16 x 16 grid of shade levels 0 to 9
    (0 = never appears, 9 = the most common value). Row = high hex digit.
    """
    highest = 0
    for count in counts:
        if count > highest:
            highest = count
    grid = []
    for row in range(16):
        cells = []
        for col in range(16):
            count = counts[row * 16 + col]
            if count == 0 or highest == 0:
                cells.append(0)
            else:
                cells.append(max(1, -(-count * 9 // highest)))
        grid.append(cells)
    return grid


# ===========================================================================
# 7. THE SAMPLE COLLECTION
# ===========================================================================
DEMO_TEXT = (
    "Cybersecurity protects systems networks and data from digital attacks. "
    "Encryption converts readable information into an unreadable form so that "
    "only authorised users with the correct key can access the original message. "
    "Entropy measures how unpredictable the symbols in a message are."
)

LONG_TEXT = (
    "Claude Shannon published A Mathematical Theory of Communication in 1948 and gave engineers a way to "
    "measure information. His idea was that a message carries information only to the extent that it is "
    "unpredictable. A coin that always lands heads tells you nothing when it lands. A fair coin tells you "
    "one bit. A page of English sits somewhere in between, because the letter e appears far more often "
    "than the letter z, and a q is almost always followed by a u. That unevenness is what makes ordinary "
    "text compressible, and it is also what classical codebreakers exploited for centuries. Count the "
    "symbols in a simple substitution cipher and the most common one is probably standing in for e. A well "
    "designed modern cipher removes that foothold. Its output is spread so evenly across all 256 byte "
    "values that counting them reveals nothing about the message underneath. An analyst who cannot decrypt "
    "a file can still learn something from its statistics alone. Low entropy suggests structure, such as "
    "text, tables or repeated records. High entropy suggests the data has been compressed, encrypted or "
    "generated at random. The measurement cannot say which of those three happened, and it cannot say "
    "whether the encryption was done well. It is a first look at the data and nothing more than that."
)


def _log_sample():
    lines = []
    for i in range(24):
        lines.append(f"2026-10-02 09:{10 + i:02d}:00 INFO login ok user=admin src=10.0.0.{1 + i % 3}")
    return "\n".join(lines)


def mixed_file(ctx):
    """Text, then an encrypted block, then text again: a test for the entropy map."""
    middle = rc4((LONG_TEXT * 2).encode("utf-8"), ctx.pass_bytes)
    return LONG_TEXT.encode("utf-8") + middle + (DEMO_TEXT * 3).encode("utf-8")


def sample_collection(ctx):
    """The fixed set of samples the project analyses: plain, transformed and encrypted."""
    long_bytes = LONG_TEXT.encode("utf-8")
    return [
        ("One symbol repeated", b"A" * 1000),
        ("Repetitive log file", _log_sample().encode("utf-8")),
        ("English paragraph", DEMO_TEXT.encode("utf-8")),
        ("Longer English passage", long_bytes),
        ("Passage, Caesar", caesar(long_bytes, ctx.shift)),
        ("Passage, rail fence", rail_fence(long_bytes, 3)),
        ("Passage, Vigenere", vigenere(long_bytes, ctx.vkey)),
        ("Passage, XOR repeating key", xor_repeating(long_bytes, ctx.pass_bytes)),
        ("Passage, Base64", base64_encode(long_bytes)),
        ("Passage, RC4 then Base64", base64_encode(rc4(long_bytes, ctx.pass_bytes))),
        ("Passage, one-time pad", one_time_pad(long_bytes, ctx.seed)),
        ("Passage, RC4", rc4(long_bytes, ctx.pass_bytes)),
        ("Random reference", random_bytes(ctx.seed ^ 0x5EED, len(long_bytes))),
        ("Counter 00 01 02 ...", counter_bytes(len(long_bytes))),
        ("Passage, RC4, sorted", sort_bytes(rc4(long_bytes, ctx.pass_bytes))),
        ("Mixed file: text + encrypted", mixed_file(ctx)),
    ]


# ===========================================================================
# 8. PREVIEWS
# ===========================================================================
def hex_preview(data, limit=192):
    parts = []
    for v in data[:limit]:
        parts.append(f"{v:02x}")
    return " ".join(parts) + (" ..." if len(data) > limit else "")


def text_preview(data, limit=420):
    chars = []
    for v in data[:limit]:
        if v == 10:
            chars.append("\n")
        elif 32 <= v < 127:
            chars.append(chr(v))
        else:
            chars.append(".")
    return "".join(chars) + (" ..." if len(data) > limit else "")


if __name__ == "__main__":
    print("This file holds the functions. Start the application with:  python main.py")
