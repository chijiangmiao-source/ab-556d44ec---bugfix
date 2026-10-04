"""Lookup-table / dynamic-symbol-table consistency tests.

The loader resolves names exclusively through DT_HASH / DT_GNU_HASH
index paths; a definition that no longer appears on those paths must
not be treated as bindable, and the first inconsistent structure slot
must be reported.
"""
import struct
import unittest

from elfaudit.audit import run_audit
from elfaudit.elf import DT_GNU_HASH, DT_HASH, ElfFile, StructuralError
from elfaudit import elf as elfmod
from elfbuilder import (
    ElfBuilder,
    corrupt_gnu_bloom,
    corrupt_gnu_bucket,
    corrupt_gnu_chain_word,
    corrupt_sysv_bucket,
    corrupt_sysv_chain_link,
    dynamic_value,
    gnu_hash_layout,
    sysv_hash_layout,
)


def provider(style, *names, soname="liba.so"):
    b = ElfBuilder(soname=soname)
    b.emit_sysv = style in ("sysv", "both")
    b.emit_gnu = style in ("gnu", "both")
    for i, n in enumerate(names):
        b.symbol(n, value=0x1000 + 0x100 * i)
    return b.build()


def consumer(style, *names, soname="fc_core.so"):
    b = ElfBuilder(soname=soname)
    b.emit_sysv = style in ("sysv", "both")
    b.emit_gnu = style in ("gnu", "both")
    b.need("liba.so")
    for n in names:
        b.symbol(n, defined=False)
    return b.build()


def expect_error(tc, data, field, needle="", object_name="liba.so"):
    with tc.assertRaises(StructuralError) as ctx:
        ElfFile.parse(data, object_name)
    tc.assertEqual(ctx.exception.field, field, ctx.exception.message)
    if needle:
        tc.assertIn(needle, ctx.exception.message)
    return ctx.exception


STYLES = ("sysv", "gnu", "both")


class ValidTables(unittest.TestCase):
    def test_each_style_parses_and_finds(self):
        for style in STYLES:
            data = provider(style, "nav_update", "log_emit", "idle_teardown")
            elf = ElfFile.parse(data, "liba.so")
            self.assertEqual(elf.find("nav_update"), [1])
            self.assertEqual(elf.find("log_emit"), [2])
            self.assertEqual(elf.find("idle_teardown"), [3])
            self.assertEqual(elf.find("missing"), [])

    def test_multiple_definitions_same_name(self):
        for style in STYLES:
            b = ElfBuilder(soname="liba.so")
            b.emit_sysv = style in ("sysv", "both")
            b.emit_gnu = style in ("gnu", "both")
            b.symbol("dup", value=0x1000).symbol("dup", value=0x2000)
            elf = ElfFile.parse(b.build(), "liba.so")
            self.assertEqual(elf.find("dup"), [1, 2])

    def test_consumer_with_undefined_symbols(self):
        for style in STYLES:
            data = consumer(style, "nav_update", "log_emit")
            elf = ElfFile.parse(data, "fc_core.so")
            self.assertEqual(elf.find("nav_update"), [1])
            self.assertEqual(elf.find("log_emit"), [2])


class SysVCorruption(unittest.TestCase):
    def test_bucket_orphans_referenced_symbol(self):
        data = provider("sysv", "nav_update")
        broken = corrupt_sysv_bucket(data, "nav_update")
        expect_error(self, broken, "DT_HASH", "not reachable")

    def test_bucket_corruption_in_dual_table(self):
        # GNU table still indexes the symbol; SysV must be rejected on
        # its own missing coverage rather than silently ignored.
        data = provider("both", "nav_update")
        broken = corrupt_sysv_bucket(data, "nav_update")
        expect_error(self, broken, "DT_HASH", "not reachable")

    def test_chain_link_splices_out_symbol(self):
        # nav_update and sym1 hash to the same SysV bucket (mod 2); the
        # builder prepends, so bucket -> sym1 -> nav_update -> 0.
        # Severing sym1's link orphans nav_update alone.
        data = provider("sysv", "nav_update", "sym1")
        broken = corrupt_sysv_chain_link(data, 2, 0)
        ctx = expect_error(self, broken, "DT_HASH", "not reachable")
        self.assertIn("nav_update", ctx.message)

    def test_first_error_is_lowest_index(self):
        data = provider("sysv", "nav_update", "idle_teardown")
        # Empty the only bucket: both symbols are orphaned; symbol 1
        # must be reported before symbol 2.
        broken = corrupt_sysv_bucket(data, "nav_update")
        ctx = expect_error(self, broken, "DT_HASH", "not reachable")
        self.assertIn("symbol 1", ctx.message)
        self.assertIn("nav_update", ctx.message)


class GnuCorruption(unittest.TestCase):
    def test_chain_word_referenced_symbol(self):
        for style in ("gnu", "both"):
            data = provider(style, "nav_update")
            broken = corrupt_gnu_chain_word(data, 1, 0x0BADF001)
            expect_error(self, broken, "DT_GNU_HASH", "does not match")

    def test_bloom_filter_rejects_symbol(self):
        data = provider("gnu", "nav_update", "log_emit")
        broken = corrupt_gnu_bloom(data, 0, 0)
        expect_error(self, broken, "DT_GNU_HASH", "bloom filter rejects")

    def test_bucket_emptied_never_passes_or_binds(self):
        # All GNU buckets zeroed: the loader finds no exports at all.
        # That can never be a successful bind; with a SysV table present
        # the count disagreement is a structural rejection, and with a
        # GNU-only object the strong reference stays unresolved.
        liba = provider("gnu", "nav_update", "log_emit")
        target = consumer("gnu", "nav_update")
        broken = corrupt_gnu_bucket(liba, 0, 0)
        verdict = run_audit(
            "fc_core.so", target, [("liba.so", broken)])
        self.assertNotEqual(verdict["status"], "passed")
        for ref in verdict.get("references", []):
            self.assertNotEqual(ref.get("status"), "bound")

        dual = provider("both", "nav_update", "log_emit")
        expect_error(self, corrupt_gnu_bucket(dual, 0, 0),
                     "DT_GNU_HASH", "symbol count")

    def test_bucket_rerouted_leaves_symbol_uncovered(self):
        data = provider("gnu", "nav_update", "log_emit")
        broken = corrupt_gnu_bucket(data, 0, 2)
        expect_error(self, broken, "DT_GNU_HASH", "not covered")

    def test_missing_end_bit_is_structural_error(self):
        data = provider("gnu", "nav_update")
        layout = gnu_hash_layout(data)
        word = struct.unpack_from("<I", data, layout["chains_off"])[0]
        broken = corrupt_gnu_chain_word(data, 1, word & ~1)
        # The non-terminating chain walks out of the indexed region;
        # whatever the first failure is, it must be located on the GNU
        # hash table rather than producing a verdict.
        verdict = run_audit(
            "fc_core.so", consumer("gnu", "nav_update"),
            [("liba.so", broken)])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["field"], "DT_GNU_HASH")
        self.assertIsInstance(verdict["error"]["offset"], int)

    def test_first_error_is_lowest_chain_slot(self):
        data = provider("gnu", "nav_update", "idle_teardown")
        broken = corrupt_gnu_chain_word(data, 1, 0xAAAAAAAA & ~1)
        broken = corrupt_gnu_chain_word(broken, 2, 0xBBBBBBBB | 1)
        ctx = expect_error(self, broken, "DT_GNU_HASH", "symbol 1")
        self.assertEqual(ctx.offset,
                         gnu_hash_layout(data)["chains_off"])


class TableDisagreement(unittest.TestCase):
    def test_sysv_missing_symbol_gnu_still_has(self):
        # Rebuild only the SysV chains so that symbol 1 drops out while
        # the GNU table remains internally consistent.
        b = ElfBuilder(soname="liba.so")
        b.symbol("nav_update", value=0x1000)
        data = b.build()
        broken = corrupt_sysv_bucket(data, "nav_update")
        # SysV validation runs first and reports the orphaned chain.
        expect_error(self, broken, "DT_HASH", "not reachable")

    def test_gnu_chain_corrupt_sysv_intact(self):
        data = provider("both", "nav_update")
        broken = corrupt_gnu_chain_word(data, 1, 0x0BADF001)
        expect_error(self, broken, "DT_GNU_HASH", "does not match")

    def test_exported_set_disagreement_detected(self):
        # Hand-craft disagreement: make the GNU bucket point past the
        # last symbol so its walk skips it, while its chain word remains.
        data = provider("both", "nav_update", "log_emit")
        layout = gnu_hash_layout(data)
        # Bucket 0 starts at symbol 2 -> symbol 1 is not covered.
        broken = corrupt_gnu_bucket(data, 0, 2)
        expect_error(self, broken, "DT_GNU_HASH", "not covered")


class ReferencedVersusUnreferenced(unittest.TestCase):
    def test_unreferenced_corrupt_symbol_still_rejects(self):
        for style in STYLES:
            liba = provider(style, "nav_update", "idle_teardown")
            target = consumer(style, "nav_update")
            if style == "gnu":
                broken = corrupt_gnu_chain_word(liba, 2, 0xCCCCCCCD)
            elif style == "sysv":
                broken = corrupt_sysv_bucket(liba, "idle_teardown")
            else:
                broken = corrupt_sysv_bucket(liba, "idle_teardown")
            verdict = run_audit(
                "fc_core.so", target, [("liba.so", broken)])
            self.assertEqual(verdict["status"], "rejected",
                             f"{style}: {verdict['status']}")
            self.assertEqual(verdict["error"]["object"], "liba.so")
            self.assertEqual(verdict["references"], [])

    def test_referenced_symbol_intact_control_passes(self):
        for style in STYLES:
            liba = provider(style, "nav_update", "idle_teardown")
            target = consumer(style, "nav_update")
            verdict = run_audit(
                "fc_core.so", target, [("liba.so", liba)])
            self.assertEqual(verdict["status"], "passed", verdict)
            (ref,) = verdict["references"]
            self.assertEqual(ref["symbol"], "nav_update")
            self.assertEqual(ref["resolution"]["object"], "liba.so")


class AuditVerdictShape(unittest.TestCase):
    def test_corrupt_dependency_is_rejected_without_partial_binding(self):
        liba = provider("both", "nav_update")
        target = consumer("both", "nav_update")
        broken = corrupt_gnu_chain_word(liba, 1, 0x0BADF001)
        verdict = run_audit(
            "fc_core.so", target, [("liba.so", broken)])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["load_order"], [])
        self.assertEqual(verdict["references"], [])
        self.assertIsNone(verdict["first_unresolved"])
        err = verdict["error"]
        self.assertEqual(err["object"], "liba.so")
        self.assertEqual(err["field"], "DT_GNU_HASH")
        self.assertIsInstance(err["offset"], int)

    def test_corrupt_target_is_rejected(self):
        liba = provider("both", "nav_update")
        broken_target = corrupt_gnu_chain_word(
            consumer("both", "nav_update"), 1, 0x0BADF001)
        verdict = run_audit(
            "fc_core.so", broken_target, [("liba.so", liba)])
        self.assertEqual(verdict["status"], "rejected")
        self.assertEqual(verdict["error"]["object"], "fc_core.so")


if __name__ == "__main__":
    unittest.main()
