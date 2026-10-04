#!/usr/bin/env python3
"""End-to-end acceptance verifier for the audit service.

Runs against a healthy ``app`` container (or a locally started server):

1.  API/HTTP smoke checks,
2.  version-shadowing scenario (earlier-loaded compatible object wins),
3.  parsing-rule unit tests (interleaved),
4.  weak-symbol scenario (weak references may stay unbound),
5.  corrupted dynamic-table scenarios (rejection with first error),
6.  corrupted lookup-index scenarios (SysV/GNU hash tables inconsistent
    with the dynamic symbol table, referenced and unreferenced symbols),
7.  frozen-verdict replay / conflict semantics.

Exits 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import base64
import json
import os
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for extra in (os.path.join(REPO, "app", "src"), os.path.join(REPO, "tools")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from elfbuilder import (  # noqa: E402
    ElfBuilder,
    corrupt_gnu_bucket,
    corrupt_gnu_chain_word,
    corrupt_sysv_bucket,
    dynamic_value,
    gnu_hash_layout,
    patch_dynamic,
)
from elfaudit.elf import (  # noqa: E402
    DT_SYMTAB,
    DT_VERSYM,
)

APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8000").rstrip("/")

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    RESULTS.append((name, ok, detail))
    mark = "PASS" if ok else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not ok:
        line += f"\n       {detail}"
    print(line, flush=True)


def http(method: str, path: str, payload=None, raw: bytes | None = None):
    """Return ``(status, body_bytes)`` for one HTTP call."""
    data = raw
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(APP_URL + path, data=data, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def post_audit(audit_id: str, target_name: str, target: bytes,
               deps: list[tuple[str, bytes]]):
    payload = {
        "audit_id": audit_id,
        "target_name": target_name,
        "target": b64(target),
        "dependencies": [{"name": n, "data": b64(d)} for n, d in deps],
    }
    return http("POST", "/audits", payload)


def wait_for_app(timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = http("GET", "/healthz")
            if status == 200:
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(0.5)
    check("app becomes healthy", False, f"no /healthz 200 within {timeout}s")
    summary_and_exit()


def summary_and_exit() -> None:
    failed = [r for r in RESULTS if not r[1]]
    print("-" * 60)
    print(f"acceptance: {len(RESULTS) - len(failed)} passed, "
          f"{len(failed)} failed")
    for name, _, detail in failed:
        print(f"  FAILED: {name} {detail}")
    sys.exit(1 if failed else 0)


# ----------------------------------------------------------------------
# fixtures
# ----------------------------------------------------------------------
def shadowing_fixtures():
    """Target + two providers of nav_update@FC_2.0 (libb impersonates liba)."""
    liba = (ElfBuilder(soname="liba.so")
            .verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xA000)
            .symbol("log_emit", value=0xA100)
            .build())
    libb = (ElfBuilder(soname="liba.so")  # replaced library, same SONAME
            .verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xB000)
            .symbol("log_emit", value=0xB100)
            .build())
    target = (ElfBuilder(soname="fc_core.so")
              .need("liba.so")
              .need("libb.so")
              .symbol("nav_update", defined=False, version="FC_2.0",
                      version_file="liba.so")
              .symbol("log_emit", defined=False)
              .build())
    return target, [("liba.so", liba), ("libb.so", libb)]


def weak_fixtures():
    liba = (ElfBuilder(soname="liba.so")
            .symbol("required_op", value=0x4000)
            .symbol("weak_choice", bind="WEAK", value=0x4100)
            .build())
    target = (ElfBuilder(soname="fc_core.so")
              .need("liba.so")
              .symbol("required_op", defined=False)
              .symbol("optional_trace", defined=False, bind="WEAK")
              .symbol("weak_choice", defined=False, bind="WEAK")
              .build())
    return target, [("liba.so", liba)]


def lookup_fixtures(style: str, extra: tuple[str, ...] = ()):
    """Provider/consumer pair for nav_update using one hash table style."""
    lib = ElfBuilder(soname="libnav.so")
    lib.emit_sysv = style in ("sysv", "both")
    lib.emit_gnu = style in ("gnu", "both")
    lib.symbol("nav_update", value=0x7000)
    for i, n in enumerate(extra):
        lib.symbol(n, value=0x8000 + 0x100 * i)
    tgt = ElfBuilder(soname="fc_lookup.so")
    tgt.emit_sysv = style in ("sysv", "both")
    tgt.emit_gnu = style in ("gnu", "both")
    tgt.need("libnav.so").symbol("nav_update", defined=False)
    return tgt.build(), [("libnav.so", lib.build())]


# ----------------------------------------------------------------------
# scenario steps
# ----------------------------------------------------------------------
def step_smoke() -> None:
    print("== API/HTTP smoke ==", flush=True)
    status, body = http("GET", "/healthz")
    check("GET /healthz -> 200", status == 200, f"got {status}: {body!r}")

    status, _ = http("GET", "/audits/never-seen")
    check("GET unknown audit -> 404", status == 404, f"got {status}")

    status, _ = http("GET", "/")
    check("GET / -> 404", status == 404, f"got {status}")

    status, _ = http("POST", "/audits", raw=b"{not json")
    check("POST malformed JSON -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/audits", {"audit_id": "x", "target_name": "t"})
    check("POST missing target -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/audits", {
        "audit_id": "bad-b64", "target_name": "t", "target": "!!!notb64!!!"})
    check("POST invalid Base64 -> 400", status == 400, f"got {status}")

    too_many = [{"name": f"lib{i}.so", "data": b64(b"x")} for i in range(9)]
    status, _ = http("POST", "/audits", {
        "audit_id": "too-many", "target_name": "t", "target": b64(b"x"),
        "dependencies": too_many})
    check("POST nine dependencies -> 400", status == 400, f"got {status}")

    status, _ = http("POST", "/elsewhere", {})
    check("POST unknown path -> 404", status == 404, f"got {status}")


def step_version_shadowing() -> dict:
    print("== version shadowing scenario ==", flush=True)
    target, deps = shadowing_fixtures()
    status, body = post_audit("shadow-1", "fc_core.so", target, deps)
    check("shadow-1 audit created", status == 201, f"got {status}: {body!r}")
    verdict = json.loads(body) if status in (200, 201) else {}

    ok = verdict.get("status") == "passed"
    check("shadow-1 verdict passed", ok, json.dumps(verdict)[:400])

    by_symbol = {r["symbol"]: r for r in verdict.get("references", [])}
    nav = by_symbol.get("nav_update", {})
    res = nav.get("resolution", {})
    check("versioned ref binds to earlier-loaded compatible object",
          res.get("object") == "liba.so",
          f"resolution={res!r}")
    check("version basis records verdef FC_2.0",
          res.get("version_basis") == {"kind": "verdef", "version": "FC_2.0",
                                       "index": 2},
          f"basis={res.get('version_basis')!r}")
    check("requirement echoes version and file",
          nav.get("requirement") == {"version": "FC_2.0", "file": "liba.so"},
          f"requirement={nav.get('requirement')!r}")
    log = by_symbol.get("log_emit", {})
    check("unversioned shadowed ref binds to first loaded object",
          log.get("resolution", {}).get("object") == "liba.so",
          f"resolution={log.get('resolution')!r}")
    check("load order is BFS first-discovery",
          verdict.get("load_order") == ["fc_core.so", "liba.so", "libb.so"],
          f"load_order={verdict.get('load_order')!r}")

    # Reversed DT_NEEDED order: the impostor now loads first and wins,
    # which is exactly what the audit is meant to make visible.
    reversed_target = (ElfBuilder(soname="fc_core.so")
                       .need("libb.so")
                       .need("liba.so")
                       .symbol("nav_update", defined=False, version="FC_2.0",
                               version_file="liba.so")
                       .build())
    status, body = post_audit("shadow-2", "fc_core.so", reversed_target, deps)
    verdict2 = json.loads(body) if status in (200, 201) else {}
    nav2 = {r["symbol"]: r for r in verdict2.get("references", [])}.get(
        "nav_update", {})
    check("reversed load order shadows to the impostor",
          nav2.get("resolution", {}).get("object") == "libb.so",
          f"resolution={nav2.get('resolution')!r}")
    return verdict


def step_unit_tests() -> None:
    print("== parsing-rule unit tests (interleaved) ==", flush=True)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(REPO, "app", "src"), os.path.join(REPO, "tools")]
        + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else []))
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s",
         os.path.join(REPO, "tests"), "-v"],
        capture_output=True, text=True, env=env)
    tail = "\n".join((proc.stderr or proc.stdout).splitlines()[-6:])
    check("parsing-rule unit tests pass", proc.returncode == 0, tail)


def step_weak_symbols() -> None:
    print("== weak symbol scenario ==", flush=True)
    target, deps = weak_fixtures()
    status, body = post_audit("weak-1", "fc_core.so", target, deps)
    check("weak-1 audit created", status == 201, f"got {status}: {body!r}")
    verdict = json.loads(body) if status in (200, 201) else {}
    check("weak-1 verdict passed despite unbound weak ref",
          verdict.get("status") == "passed", json.dumps(verdict)[:400])
    by_symbol = {r["symbol"]: r for r in verdict.get("references", [])}
    weak = by_symbol.get("optional_trace", {})
    check("weak ref stays unbound with reason",
          weak.get("status") == "unbound"
          and "no visible definition" in weak.get("reason", ""),
          f"ref={weak!r}")
    check("no first_unresolved for weak-only misses",
          verdict.get("first_unresolved") is None,
          f"first_unresolved={verdict.get('first_unresolved')!r}")
    check("strong ref bound to provider",
          by_symbol.get("required_op", {}).get("resolution", {}).get("object")
          == "liba.so", f"ref={by_symbol.get('required_op')!r}")
    check("weak ref with definition is bound",
          by_symbol.get("weak_choice", {}).get("status") == "bound",
          f"ref={by_symbol.get('weak_choice')!r}")

    # Strong reference without any definition must fail the verdict.
    bad_target = (ElfBuilder(soname="fc_core.so")
                  .need("liba.so")
                  .symbol("missing_op", defined=False)
                  .build())
    status, body = post_audit("weak-2", "fc_core.so", bad_target, deps)
    verdict2 = json.loads(body) if status in (200, 201) else {}
    first = verdict2.get("first_unresolved") or {}
    check("strong unbound ref fails the verdict",
          verdict2.get("status") == "failed"
          and first.get("symbol") == "missing_op"
          and "no visible definition" in first.get("reason", ""),
          json.dumps(verdict2)[:400])


def step_corrupted_tables() -> None:
    print("== corrupted dynamic table scenarios ==", flush=True)
    target, deps = shadowing_fixtures()

    # Unmappable DT_SYMTAB (virtual address outside every PT_LOAD).
    broken = patch_dynamic(target, DT_SYMTAB, 0x00DEAD0000)
    status, body = post_audit("corrupt-1", "fc_core.so", broken, deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    err = verdict.get("error") or {}
    check("unmappable symbol table rejected with first error located",
          verdict.get("status") == "rejected"
          and err.get("field") == "DT_SYMTAB"
          and err.get("object") == "fc_core.so",
          json.dumps(verdict)[:400])

    # Truncated object.
    status, body = post_audit("corrupt-2", "fc_core.so", target[:100], deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("truncated object rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") in ("e_phoff", "e_ident"),
          json.dumps(verdict)[:400])

    # Contradictory version reference: hidden version on an undefined
    # symbol (versym of symbol index 1 gets the hidden bit).
    versym_off = dynamic_value(target, DT_VERSYM)
    raw = bytearray(target)
    raw[versym_off + 3] |= 0x80  # hidden bit (0x8000) of versym[1], LE high byte
    status, body = post_audit("corrupt-3", "fc_core.so", bytes(raw), deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("contradictory version reference rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_VERSYM",
          json.dumps(verdict)[:400])

    # Missing dependency object.
    status, body = post_audit("corrupt-4", "fc_core.so", target, deps[:1])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("missing dependency rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_NEEDED"
          and "libb.so" in verdict.get("error", {}).get("message", ""),
          json.dumps(verdict)[:400])

    # Duplicate object names in the request.
    status, body = post_audit("corrupt-5", "fc_core.so", target,
                              [deps[0], deps[0]])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("duplicate object names rejected",
          verdict.get("status") == "rejected"
          and "duplicate" in verdict.get("error", {}).get("message", ""),
          json.dumps(verdict)[:400])


def step_lookup_index_corruption() -> None:
    print("== corrupted lookup-index scenarios ==", flush=True)

    # Valid objects of each index style must keep binding normally.
    for style in ("sysv", "gnu", "both"):
        target, deps = lookup_fixtures(style)
        status, body = post_audit(f"lookup-ok-{style}", "fc_lookup.so",
                                  target, deps)
        verdict = json.loads(body) if status in (200, 201) else {}
        refs = {r["symbol"]: r for r in verdict.get("references", [])}
        check(f"valid {style} lookup table passes and binds",
              status == 201 and verdict.get("status") == "passed"
              and refs.get("nav_update", {}).get("resolution", {})
              .get("object") == "libnav.so",
              f"got {status}: {json.dumps(verdict)[:300]}")

    # Direct dependency keeps a same-named definition but its lookup
    # index can no longer reach it: each index format must be rejected.
    target, deps = lookup_fixtures("sysv")
    broken = corrupt_sysv_bucket(deps[0][1], "nav_update")
    status, body = post_audit("lookup-sysv-broken", "fc_lookup.so", target,
                              [("libnav.so", broken)])
    verdict = json.loads(body) if status in (200, 201) else {}
    err = verdict.get("error") or {}
    check("SysV-only broken lookup rejected with same-named definition",
          status == 201 and verdict.get("status") == "rejected"
          and err.get("object") == "libnav.so"
          and err.get("field") == "DT_HASH"
          and verdict.get("references") == []
          and verdict.get("load_order") == [],
          json.dumps(verdict)[:400])

    target, deps = lookup_fixtures("gnu")
    layout = gnu_hash_layout(deps[0][1])
    word = struct.unpack_from("<I", deps[0][1], layout["chains_off"])[0]
    broken = corrupt_gnu_chain_word(
        deps[0][1], 1, 0x0BADF001)  # force chain-end bit on single-symbol chain
    status, body = post_audit("lookup-gnu-broken", "fc_lookup.so", target,
                              [("libnav.so", broken)])
    verdict = json.loads(body) if status in (200, 201) else {}
    err = verdict.get("error") or {}
    check("GNU-only broken chain word rejected at the exact slot",
          verdict.get("status") == "rejected"
          and err.get("object") == "libnav.so"
          and err.get("field") == "DT_GNU_HASH"
          and "nav_update" in err.get("message", "")
          and err.get("offset") == layout["chains_off"]
          and verdict.get("references") == [],
          json.dumps(verdict)[:400])

    # Both tables present: each table is independently cross-checked.
    target, deps = lookup_fixtures("both")
    broken = corrupt_sysv_bucket(deps[0][1], "nav_update")
    status, body = post_audit("lookup-both-sysv-broken", "fc_lookup.so",
                              target, [("libnav.so", broken)])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("dual tables: corrupted SysV side rejected even though GNU is fine",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_HASH",
          json.dumps(verdict)[:400])

    target, deps = lookup_fixtures("both")
    layout = gnu_hash_layout(deps[0][1])
    word = struct.unpack_from("<I", deps[0][1], layout["chains_off"])[0]
    broken = corrupt_gnu_chain_word(
        deps[0][1], 1, 0x0BADF001)  # force chain-end bit on single-symbol chain
    status, body = post_audit("lookup-both-gnu-broken", "fc_lookup.so",
                              target, [("libnav.so", broken)])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("dual tables: corrupted GNU side rejected even though SysV is fine",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_GNU_HASH",
          json.dumps(verdict)[:400])

    # Bloom filter that rejects a present symbol.
    target, deps = lookup_fixtures("gnu")
    lib = bytearray(deps[0][1])
    bloff = gnu_hash_layout(deps[0][1])["bloom_off"]
    lib[bloff:bloff + 8] = b"\0" * 8
    status, body = post_audit("lookup-gnu-bloom", "fc_lookup.so", target,
                              [("libnav.so", bytes(lib))])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("GNU bloom filter rejecting a present symbol is rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_GNU_HASH"
          and "bloom" in verdict.get("error", {}).get("message", ""),
          json.dumps(verdict)[:400])

    # Dual-table disagreement: reroute the GNU bucket so one exported
    # symbol drops off the GNU chains while SysV still indexes it.
    target, deps = lookup_fixtures("both", ("idle_teardown",))
    broken = corrupt_gnu_bucket(deps[0][1], 0, 2)
    status, body = post_audit("lookup-dual-disagree", "fc_lookup.so",
                              target, [("libnav.so", broken)])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("dual tables disagreeing on indexed symbols are rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("field") == "DT_GNU_HASH"
          and "nav_update" in verdict.get("error", {}).get("message", ""),
          json.dumps(verdict)[:400])

    # Corruption of an unreferenced symbol: the request only binds
    # nav_update, yet the object must still be rejected and the error
    # must stably pinpoint the damaged symbol's slot for every style.
    for style, corrupt_kw in (
            ("sysv", {"kind": "sysv_bucket"}),
            ("gnu", {"kind": "gnu_word"}),
            ("both", {"kind": "sysv_bucket"})):
        target, deps = lookup_fixtures(style, ("idle_teardown",))
        lib = deps[0][1]
        if corrupt_kw["kind"] == "sysv_bucket":
            broken = corrupt_sysv_bucket(lib, "idle_teardown")
            field = "DT_HASH"
        else:
            broken = corrupt_gnu_chain_word(lib, 2, 0xCCCCCCCD)
            field = "DT_GNU_HASH"
        payloads = []
        errors = []
        for n in ("lookup-unref-1", "lookup-unref-2"):
            status, body = post_audit(f"{n}-{style}", "fc_lookup.so", target,
                                      [("libnav.so", broken)])
            verdict = json.loads(body) if status in (200, 201) else {}
            payloads.append(verdict)
            errors.append(verdict.get("error") or {})
        same = (errors[0] == errors[1]
                and all(e.get("field") == field for e in errors))
        check(f"{style}: unreferenced corrupted symbol stably located ({field})",
              all(v.get("status") == "rejected" for v in payloads)
              and same
              and all(v.get("references") == [] for v in payloads)
              and "idle_teardown" in errors[0].get("message", ""),
              json.dumps(payloads[0])[:400])

    # Corruption in the target object itself is rejected, not in a dep.
    target, deps = lookup_fixtures("gnu")
    layout = gnu_hash_layout(target)
    word = struct.unpack_from("<I", target, layout["chains_off"])[0]
    broken_target = corrupt_gnu_chain_word(
        target, 1, 0x0BADF001)  # force chain-end bit on single-symbol chain
    status, body = post_audit("lookup-target-broken", "fc_lookup.so",
                              broken_target, deps)
    verdict = json.loads(body) if status in (200, 201) else {}
    check("corrupted lookup index in the target object is rejected",
          verdict.get("status") == "rejected"
          and verdict.get("error", {}).get("object") == "fc_lookup.so"
          and verdict.get("error", {}).get("field") == "DT_GNU_HASH",
          json.dumps(verdict)[:400])

    # When two symbols are damaged the first one (lowest index) is the
    # located structural error, deterministically.
    target, deps = lookup_fixtures("gnu", ("idle_teardown",))
    broken = corrupt_gnu_chain_word(deps[0][1], 1, 0xAAAAAAAA)  # even: chain continues
    broken = corrupt_gnu_chain_word(broken, 2, 0xBBBBBBBF)      # odd: chain ends
    status, body = post_audit("lookup-first-error", "fc_lookup.so", target,
                              [("libnav.so", broken)])
    verdict = json.loads(body) if status in (200, 201) else {}
    check("first structural error is the lowest damaged slot",
          verdict.get("status") == "rejected"
          and "symbol 1" in verdict.get("error", {}).get("message", "")
          and "nav_update" in verdict.get("error", {}).get("message", "")
          and verdict.get("error", {}).get("offset")
          == gnu_hash_layout(deps[0][1])["chains_off"],
          json.dumps(verdict)[:400])


def step_replay_and_conflict(frozen: dict) -> None:
    print("== frozen verdict replay / conflict ==", flush=True)
    target, deps = shadowing_fixtures()

    status, body = post_audit("shadow-1", "fc_core.so", target, deps)
    check("identical replay returns 200 with frozen verdict",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")

    status, body = http("GET", "/audits/shadow-1")
    check("GET replays the same frozen verdict",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")

    tampered = deps[1][1][:-1] + bytes([deps[1][1][-1] ^ 0x01])
    status, _ = post_audit("shadow-1", "fc_core.so", target,
                           [("liba.so", deps[0][1]), ("libb.so", tampered)])
    check("replaced dependency object conflicts (409)", status == 409,
          f"got {status}")

    status, _ = post_audit("shadow-1", "fc_renamed.so", target, deps)
    check("renamed target conflicts (409)", status == 409, f"got {status}")

    status, body = http("GET", "/audits/shadow-1")
    check("original verdict still readable after conflicts",
          status == 200 and json.loads(body) == frozen,
          f"got {status}: {body!r}")

    status, body = post_audit("shadow-3", "fc_core.so", target, deps)
    check("same request under a new audit id is independent",
          status == 201 and json.loads(body)["audit_id"] == "shadow-3",
          f"got {status}")


def main() -> None:
    wait_for_app()
    step_smoke()
    frozen = step_version_shadowing()
    step_unit_tests()
    step_weak_symbols()
    step_corrupted_tables()
    step_lookup_index_corruption()
    step_replay_and_conflict(frozen)
    summary_and_exit()


if __name__ == "__main__":
    main()
