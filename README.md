# Entropy Lab - G6

**Mini Project-1, P6: Entropy-Based Analysis of Encrypted Data**
Group G6

A menu-driven Python application that studies the statistical distribution of
data and its Shannon entropy, to see how far entropy can tell plain, encoded and
encrypted data apart without decrypting anything.

## Team

| Member | Primary role |
|---|---|
| Anupama | Mathematical modelling |
| Hari | Implementation and coding |
| Karthika | Algorithm design |
| Nisha | Presentation and technical communication |
| Rohit | Project coordination and data experimentation |
| Sreerag | Documentation |
| Vandana | Testing and validation |

## Repository contents

| Path | What it is |
|---|---|
| `main.py` | The menu-driven application. Start here |
| `entropy_core.py` | Entropy, statistics, transformations and experiments, all hand-written |
| `test_core.py` | Known-answer tests |
| `app.py`, `static/index.html` | Optional visual dashboard (Flask, HTML, CSS, JavaScript) |
| `docs/` | Mathematical model and presentation |

## Run it

Needs Python 3.8 or newer. No packages to install.

```
python main.py
```

## The menu

New users should start with option 11, the guided demo. Every screen ends with
a "What this means" box in plain English.

| Option | What it does | Brief deliverable |
|---|---|---|
| 1. Load data | Type text, open a file, or pick one of 16 built-in samples | Prepare data samples |
| 2. Byte frequencies and entropy | Count, probability and contribution of each byte value, a labelled gauge and a 16 x 16 byte map | Frequency of byte values; entropy method |
| 3. Entropy map | Entropy window by window along the data, to find encrypted or compressed regions | Analyse the samples |
| 4. Profile and verdict | Shannon entropy, min-entropy, order check, chi-square, index of coincidence, compared with random data of the same size, then a verdict with reasons | Are high and low entropy samples distinguishable? |
| 5. Transform and compare | Same input through every method, with H, dH and the order check | Calculate and compare entropy |
| 6. Compare the sample collection | All 16 samples sorted by entropy, each with a verdict | Distinguishable characteristics |
| 7. Sample-size experiment | Entropy from 16 to 65,536 bytes | Effect of sample size |
| 8. Modify the distribution | Replace 0% to 100% of bytes with random ones | Modify the distribution |
| 9. Build a distribution | Choose the number of symbols and the skew | Modify the distribution |
| 10. Limitations of entropy | Four measured cases where entropy misleads | Limitations |
| 11. Guided demo | The whole project in nine steps, with an explanation at each | Presentation |
| 12. Glossary | Plain definitions of every term on screen | |
| 13. Settings | Keys, preprocessing, colour on or off | |
| 14. Visual dashboard | Optional web view (needs Flask) | |

## The statistics

All in `entropy_core.py`, written by hand.

| Statistic | Formula | What it shows |
|---|---|---|
| Shannon entropy | H = -sum p log2 p | Average unpredictability, 0 to 8 bits per byte |
| Min-entropy | -log2(highest p) | Worst case: how good the single best guess is |
| Order check | Entropy of (next byte - this byte) mod 256 | Whether each byte predicts the next. Catches sorted and counter data, which Shannon entropy misses |
| Chi-square | sum (observed - expected)^2 / expected, shown as a z-score | Whether the counts are as even as chance allows. Random: -3 to +3 |
| Index of coincidence | sum f(f-1) / N(N-1), letters only | English 0.067, random letters 0.038. Separates Caesar from Vigenere |
| Entropy map | Entropy per window | Where in a file the high-entropy data is |
| Verdict | Rules combining the above | What kind of data the sample looks like, and why |

Every statistic is compared with random data of the same size, because small
samples read lower than 8 even when they are random.

## How the rules are met

- **No cryptography or other dedicated libraries.** `entropy_core.py` imports
  only `math` (for `log2`). Every cipher, the Base64 encoder and the random
  generator are written by hand.
- **No ready-made functions for the core operations.** Byte frequencies are
  counted with a plain loop, probabilities are `count / total`, and entropy is
  summed term by term.
- **Menu-driven.** `main.py` is a numbered console menu.
- **Statistics only.** The program never decrypts anything and never tries to
  break a cipher.

## Methods

All written by hand in `entropy_core.py`.

| Type | Methods | Why it is included |
|---|---|---|
| Classical | Caesar, Vigenere, Rail fence | Substitution and transposition. Caesar and rail fence leave entropy unchanged |
| Stream | XOR with repeating key, one-time pad, RC4 | XOR-based encryption that pushes entropy towards 8 |
| Transform and reference | Base64, random reference | An encoding with no key, and a uniform baseline |

## Files in detail

| File | What it is |
|---|---|
| `main.py` | The menu-driven application. Start here |
| `entropy_core.py` | Frequency counting, entropy, the transformations and the experiments |
| `test_core.py` | 37 known-answer tests |
| `app.py`, `static/index.html` | Optional visual dashboard. Uses the same functions from `entropy_core.py` |

## Tests

```
python -m unittest test_core -v
```

They check, among others: HELLO = 1.9219 bits, Caesar and rail fence leave
entropy unchanged, RC4 and Base64 against published answers, and that no
sample exceeds its ceiling of log2(N).

## Optional extras

```
pip install flask pypdf
```

- **Flask** enables menu option 10, the visual dashboard.
- **pypdf** lets the program read the text inside a PDF. Without it, a PDF is
  analysed as raw bytes.

Neither is used for any calculation.

## Limits

- Inputs over 200,000 bytes are cut to the first 200,000.
- Base64 text has 65 possible symbols (64 characters and the `=` padding sign), so its ceiling is log2(65), about 6.02 bits.
- Colour is used when the console supports it. Turn it off in Settings, or set the NO_COLOR environment variable.
- All console output is plain ASCII, so it prints on any Windows, macOS or Linux console.
- The random generator (xorshift) is for experiments only. It is not secure.
- The one-time pad uses that generator for its key so results repeat. A real
  one-time pad needs a truly random key.
