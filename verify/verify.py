#!/usr/bin/env python3
"""End-to-end acceptance verifier for the audit service.

Runs against a healthy ``app`` container (or a locally started server):

1.  API/HTTP smoke checks,
2.  version-shadowing scenario (earlier-loaded compatible object wins),
3.  parsing-rule unit tests (interleaved),
4.  weak-symbol scenario (weak references may stay unbound),
5.  corrupted dynamic-table scenarios (rejection with first error),
6.  corrupted dynamic lookup metadata (SysV/GNU index paths that can no
    longer reach their own symbols are rejected, never bound),
7.  frozen-verdict replay / conflict semantics.

Exits 0 when every check passes, 1 otherwise.
"""
from __future__ import annotations

import base64
import json
import os
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
    corrupt_gnu_symbol_hash,
    dynamic_value,
    orphan_sysv_symbol,
    patch_dynamic,
)
from elfaudit.elf import DT_SYMTAB, DT_VERSYM  # noqa: E402

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


def lookup_fixtures(sysv: bool = True, gnu: bool = True):
    """Target strongly references nav_update@FC_2.0; the dependency
    exports it plus an export nothing references (``spare``)."""
    b = ElfBuilder(soname="liba.so")
    b.emit_sysv, b.emit_gnu = sysv, gnu
    liba = (b.verdef("FC_2.0")
            .symbol("nav_update", version="FC_2.0", value=0xA000)
            .symbol("spare", value=0xA200)
            .build())
    target = (ElfBuilder(soname="fc_core.so")
              .need("liba.so")
              .symbol("nav_update", defined=False, version="FC_2.0",
                      version_file="liba.so")
              .build())
    return target, liba


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


def step_corrupted_lookup_tables() -> None:
    print("== corrupted dynamic lookup metadata ==", flush=True)

    # Healthy objects with each index format (SysV only, GNU only, both)
    # must bind normally.
    for label, sysv, gnu in (("sysv-only", True, False),
                             ("gnu-only", False, True),
                             ("dual-table", True, True)):
        target, liba = lookup_fixtures(sysv=sysv, gnu=gnu)
        status, body = post_audit(f"lookup-ok-{label}", "fc_core.so", target,
                                  [("liba.so", liba)])
        verdict = json.loads(body) if status in (200, 201) else {}
        refs = {r["symbol"]: r for r in verdict.get("references", [])}
        nav = refs.get("nav_update", {})
        check(f"healthy {label} dependency binds nav_update",
              verdict.get("status") == "passed"
              and nav.get("resolution", {}).get("object") == "liba.so",
              json.dumps(verdict)[:400])

    def expect_rejection(audit_id: str, liba: bytes, field: str,
                         needle: str) -> None:
        target, _ = lookup_fixtures()
        status, body = post_audit(audit_id, "fc_core.so", target,
                                  [("liba.so", liba)])
        verdict = json.loads(body) if status in (200, 201) else {}
        err = verdict.get("error") or {}
        ok = (verdict.get("status") == "rejected"
              and err.get("object") == "liba.so"
              and err.get("field") == field
              and needle in err.get("message", "")
              # no partial binding or success verdict for the request
              and verdict.get("references") == []
              and verdict.get("first_unresolved") is None)
        check(f"{audit_id}: corrupted lookup metadata rejected "
              f"({field})", ok, json.dumps(verdict)[:400])

    # The incident: the direct dependency still contains a same-named
    # definition of nav_update, but its SysV lookup data no longer
    # reaches it.  This must be rejected, not bound.
    _, liba = lookup_fixtures()
    expect_rejection("lookup-1", orphan_sysv_symbol(liba, "nav_update"),
                     "DT_HASH", "nav_update")

    # SysV-only index, same corruption.
    _, liba = lookup_fixtures(gnu=False)
    expect_rejection("lookup-2", orphan_sysv_symbol(liba, "nav_update"),
                     "DT_HASH", "nav_update")

    # GNU-only index, chain value no longer matches the symbol name.
    _, liba = lookup_fixtures(sysv=False)
    expect_rejection("lookup-3", corrupt_gnu_symbol_hash(liba, 1),
                     "DT_GNU_HASH", "nav_update")

    # Both tables present but disagreeing: the GNU side is corrupted
    # while the SysV side still finds the symbol.
    _, liba = lookup_fixtures()
    expect_rejection("lookup-4", corrupt_gnu_symbol_hash(liba, 1),
                     "DT_GNU_HASH", "nav_update")

    # The corrupted symbol is one nothing references ('spare'); the
    # object is still rejected at parse time.
    _, liba = lookup_fixtures()
    expect_rejection("lookup-5", corrupt_gnu_symbol_hash(liba, 2),
                     "DT_GNU_HASH", "spare")


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
    step_corrupted_lookup_tables()
    step_replay_and_conflict(frozen)
    summary_and_exit()


if __name__ == "__main__":
    main()
