"""
test_core.py
============
Known-answer tests for entropy_core.py.

Run:
    python -m unittest test_core -v
"""

import unittest

import entropy_core as core


class FrequencyAndEntropyTests(unittest.TestCase):
    def test_counts_are_correct(self):
        counts = core.count_bytes(b"HELLO")
        self.assertEqual(counts[ord("L")], 2)
        self.assertEqual(counts[ord("H")], 1)
        self.assertEqual(sum(counts), 5)
        self.assertEqual(core.count_distinct(counts), 4)

    def test_hello_matches_hand_calculation(self):
        self.assertAlmostEqual(core.shannon_entropy(b"HELLO"), 1.9219, places=4)

    def test_single_symbol_is_zero(self):
        self.assertEqual(core.shannon_entropy(b"AAAA"), 0.0)

    def test_empty_input_is_zero(self):
        self.assertEqual(core.shannon_entropy(b""), 0.0)

    def test_n_equally_likely_symbols_give_log2_n(self):
        self.assertAlmostEqual(core.shannon_entropy(b"ABCDEFGH"), 3.0)
        self.assertAlmostEqual(core.shannon_entropy(bytes(range(256))), 8.0)

    def test_order_does_not_matter(self):
        self.assertAlmostEqual(core.shannon_entropy(b"ABABABAB"), core.shannon_entropy(b"AABBAABB"))

    def test_frequency_table_adds_up_to_entropy(self):
        data = core.DEMO_TEXT.encode()
        rows = core.frequency_table(data)
        self.assertAlmostEqual(sum(row[2] for row in rows), 1.0)
        self.assertAlmostEqual(sum(row[3] for row in rows), core.shannon_entropy(data))


class TransformationTests(unittest.TestCase):
    def test_caesar_hello(self):
        self.assertEqual(core.caesar(b"HELLO", 3), b"KHOOR")

    def test_caesar_keeps_entropy(self):
        text = core.DEMO_TEXT.encode()
        self.assertAlmostEqual(core.shannon_entropy(core.caesar(text, 3)), core.shannon_entropy(text))

    def test_vigenere_textbook_example(self):
        self.assertEqual(core.vigenere(b"ATTACKATDAWN", "LEMON"), b"LXFOPVEFRNHR")

    def test_rail_fence_textbook_example(self):
        self.assertEqual(core.rail_fence(b"WEAREDISCOVEREDFLEEATONCE", 3), b"WECRLTEERDSOEEFEAOCAIVDEN")

    def test_rail_fence_keeps_entropy(self):
        text = core.DEMO_TEXT.encode()
        self.assertAlmostEqual(core.shannon_entropy(core.rail_fence(text)), core.shannon_entropy(text))

    def test_xor_twice_returns_input(self):
        self.assertEqual(core.xor_repeating(core.xor_repeating(b"entropy", b"key"), b"key"), b"entropy")

    def test_rc4_published_vectors(self):
        self.assertEqual(core.rc4(b"Plaintext", b"Key").hex(), "bbf316e8d940af0ad3")
        self.assertEqual(core.rc4(b"pedia", b"Wiki").hex(), "1021bf0420")

    def test_base64_known_answers(self):
        self.assertEqual(core.base64_encode(b"Many hands make light work."), b"TWFueSBoYW5kcyBtYWtlIGxpZ2h0IHdvcmsu")
        self.assertEqual(core.base64_encode(b"a"), b"YQ==")
        self.assertEqual(core.base64_encode(b"ab"), b"YWI=")

    def test_generator_repeats_and_looks_uniform(self):
        self.assertEqual(core.random_bytes(42, 100), core.random_bytes(42, 100))
        self.assertGreater(core.shannon_entropy(core.random_bytes(42, 65536)), 7.99)


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.ctx = core.Context()
        self.plain = core.preprocess(core.DEMO_TEXT.encode())

    def test_letters_only_mode_matches_the_hand_model(self):
        az = core.preprocess(core.DEMO_TEXT.encode(), "az")
        self.assertEqual(len(az), 241)
        self.assertAlmostEqual(core.shannon_entropy(az), 4.0852, places=4)
        self.assertAlmostEqual(core.shannon_entropy(core.vigenere(az, "SECURE")), 4.5102, places=4)

    def test_every_method_runs(self):
        results = core.analyse(self.plain, self.ctx)
        self.assertEqual(len(results), len(core.METHODS) + 1)
        for r in results:
            self.assertTrue(0.0 <= r["H"] <= 8.0)

    def test_base64_never_passes_its_ceiling(self):
        # 64 characters plus the "=" padding sign: at most log2(65) bits
        for data in (core.rc4(self.plain, self.ctx.pass_bytes), bytes(range(256)), core.random_bytes(7, 5000)):
            self.assertLessEqual(core.shannon_entropy(core.base64_encode(data)), core.LOG2_65)

    def test_base64_matches_the_standard_alphabet_only(self):
        allowed = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        self.assertTrue(set(core.base64_encode(bytes(range(256)))) <= allowed)

    def test_all_program_text_is_plain_ascii(self):
        # so the menu prints on any console, whatever its encoding
        for name in ("entropy_core.py", "main.py"):
            with open(name, encoding="utf-8") as f:
                f.read().encode("ascii")
        for card in core.limitations(self.plain, self.ctx):
            (card["h"] + card["p"] + card["a"][0] + card["a"][2] + card["b"][0] + card["b"][2]).encode("ascii")
        for m in [core.PLAIN] + core.METHODS:
            (m.name + m.describe(self.ctx) + m.reads).encode("ascii")

    def test_sample_size_never_passes_its_ceiling(self):
        s = core.size_experiment(self.plain, self.ctx)
        for series in ("plain", "cipher", "rand"):
            for value, ceiling in zip(s[series], s["ceil"]):
                self.assertLessEqual(value, ceiling + 1e-9)
        self.assertGreater(s["cipher"][-1], 7.99)

    def test_noise_starts_at_plaintext_entropy_and_rises(self):
        z = core.noise_experiment(self.plain)
        self.assertAlmostEqual(z["H"][0], core.shannon_entropy(self.plain))
        self.assertGreater(z["H"][100], z["H"][0])
        self.assertEqual(sum(z["counts"][100]), len(self.plain))

    def test_uniform_distribution_hits_ceiling(self):
        self.assertAlmostEqual(core.shape_distribution(256, 0)["H"], 8.0)

    def test_sorted_ciphertext_has_same_entropy(self):
        card = core.limitations(self.plain, self.ctx)[2]
        self.assertAlmostEqual(card["a"][1], card["b"][1])

    def test_predictable_counter_reads_as_maximum(self):
        self.assertAlmostEqual(core.shannon_entropy(core.counter_bytes(2560)), 8.0)

    def test_bands(self):
        self.assertEqual(core.classify(4.2, 1000), "Structured, text-like")
        self.assertEqual(core.classify(7.9, 1000), "High entropy: encrypted, compressed or random")
        self.assertEqual(core.classify(1.9, 5), "Too few bytes to judge")


class AdvancedStatisticsTests(unittest.TestCase):
    def setUp(self):
        self.ctx = core.Context()
        self.text = core.LONG_TEXT.encode()

    def test_min_entropy_hello(self):
        # L is the most common letter: p = 2/5, so -log2(0.4) = 1.3219
        self.assertAlmostEqual(core.min_entropy(core.count_bytes(b"HELLO"), 5), 1.3219, places=4)

    def test_min_entropy_never_above_shannon(self):
        for data in (self.text, core.rc4(self.text, self.ctx.pass_bytes), b"A" * 50):
            counts = core.count_bytes(data)
            self.assertLessEqual(core.min_entropy(counts, len(data)), core.entropy_from_counts(counts, len(data)) + 1e-12)

    def test_order_check_catches_counter_and_sorted_data(self):
        cipher = core.rc4(self.text, self.ctx.pass_bytes)
        self.assertEqual(core.order_entropy(core.counter_bytes(1000)), 0.0)
        self.assertLess(core.order_entropy(core.sort_bytes(cipher)), 1.5)
        self.assertGreater(core.order_entropy(cipher), 7.5)

    def test_chi_square(self):
        even = core.counter_bytes(2560)
        self.assertEqual(core.chi_square(core.count_bytes(even), len(even)), 0.0)
        self.assertLess(core.chi_square_z(0.0), -20)
        rnd = core.random_bytes(99, 65536)
        self.assertLess(abs(core.chi_square_z(core.chi_square(core.count_bytes(rnd), len(rnd)))), 3)

    def test_index_of_coincidence(self):
        self.assertEqual(core.index_of_coincidence(b"AAAA")[0], 1.0)
        self.assertIsNone(core.index_of_coincidence(b"1234")[0])
        ic_text = core.index_of_coincidence(self.text)[0]
        self.assertAlmostEqual(ic_text, core.index_of_coincidence(core.caesar(self.text, 7))[0])
        self.assertLess(core.index_of_coincidence(core.vigenere(self.text, "SECURE"))[0], ic_text)

    def test_entropy_map_finds_the_encrypted_block(self):
        data = core.mixed_file(self.ctx)
        regions = core.high_entropy_regions(core.entropy_map(data, 256))
        self.assertEqual(len(regions), 1)
        start, end = regions[0]
        encrypted_start = len(core.LONG_TEXT)
        encrypted_end = encrypted_start + 2 * len(core.LONG_TEXT)
        self.assertLessEqual(abs(start - encrypted_start), 256)
        self.assertLessEqual(abs(end - encrypted_end), 256)

    def test_entropy_map_covers_all_bytes(self):
        for n in (10, 256, 1000, 50000):
            windows = core.entropy_map(bytes(n), 256)
            self.assertEqual(sum(w[1] for w in windows), n)
            self.assertLessEqual(len(windows), 64)

    def test_byte_map(self):
        grid = core.byte_map(core.count_bytes(b"AAB"))
        self.assertEqual(grid[4][1], 9)          # 'A' = 0x41, the most common value
        self.assertEqual(grid[4][2], 5)          # 'B' = 0x42, half as common
        self.assertEqual(grid[0][0], 0)

    def test_verdicts_separate_the_samples(self):
        expected = {
            "One symbol repeated": "Almost constant",
            "Longer English passage": "Readable text",
            "Passage, Caesar": "Readable text",
            "Passage, Vigenere": "Text with flattened",
            "Passage, XOR repeating key": "Structured binary",
            "Passage, Base64": "Encoded text",
            "Passage, RC4": "Looks random",
            "Counter 00 01 02 ...": "High entropy, but in a predictable order",
            "Passage, RC4, sorted": "High entropy, but in a predictable order",
            "Mixed file: text + encrypted": "Mixed",
        }
        for name, data in core.sample_collection(self.ctx):
            if name in expected:
                label = core.verdict(core.profile(data))[0]
                self.assertTrue(label.startswith(expected[name]), f"{name}: {label}")

    def test_tiny_samples_are_not_judged(self):
        self.assertEqual(core.verdict(core.profile(b"HELLO"))[0], "Too little data to judge")


if __name__ == "__main__":
    unittest.main(verbosity=2)
