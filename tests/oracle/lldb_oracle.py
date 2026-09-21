#!/usr/bin/env python3
"""lldb-as-oracle v2: judge machre's static predictions by ADDRESS against the live process.

Fixups: raw slot value -> `image lookup -a` (unslid addr + name) vs `image lookup -n <machre symbol>`.
Classified: exact / alias (same address, other preferred name) / reexport (forwarding stub) /
tlv-rewrite (dyld replaces __tlv_bootstrap with _tlv_get_addr) / objc-class (runtime class name) / FAIL.
Rebases: slot value == decoded target (slide 0) or == the file word (legacy).
Function starts: lldb symbol range must begin exactly at machre's start.
ObjC: live runtime IMP of every method/class method == machre's decoded imp; class must exist.
"""
import json, os, re, struct, subprocess
M = "/Users/bcann/programming/mac-security/machre/zig-out/bin/machre"
CORP = "/Users/bcann/programming/mac-security/machre/tests/corpus"
ENV = dict(os.environ, _ZO_DOCTOR="0")
FIX = ["hello-c","hello-objc","hello-usedylib","legacy-bind","hello-zig","hello-adhoc","hello-entitled",
       "hello-fat","hello-quarantined","hello-unsigned","fake-upx","fake-packed","high-entropy"]

def mj(cmd, p):
    r = subprocess.run([M, cmd, "--json","--arch","arm64","--limit","0","--no-security", p], capture_output=True, text=True, timeout=60)
    return (json.loads(r.stdout)["arches"][0] if r.stdout.strip() else {})
def hx(s): return int(s,16) if isinstance(s,str) else int(s)
def sym1(s): return s[1:] if s.startswith("_") else s

def run_lldb(p, cmds):
    a = ["lldb","--batch","-o","settings set interpreter.stop-command-source-on-error false","-o","breakpoint set -n main","-o","run"]
    for c in cmds: a += ["-o", c]
    a += ["-o","kill","--",p]
    out = subprocess.run(a, capture_output=True, text=True, timeout=300, env=ENV).stdout
    blocks = {}
    for chunk in out.split("(lldb) ")[1:]:
        line, _, body = chunk.partition("\n")
        blocks.setdefault(line.strip(), body)
    if os.environ.get("ORACLE_DEBUG"):
        print(f"DEBUG lldb: sent {len(cmds)+4} commands, saw {out.count('(lldb) ')} prompts; tail:", repr(out[-900:]))
        for k,b in blocks.items():
            if "error:" in b: print("DEBUG command errored:", k, "->", b.strip().splitlines()[0][:100])
    return out, blocks

def parse_lookup(body):
    """-> list of (unslid_addr or None, module, summary)"""
    res = []
    for m in re.finditer(r"Address: (\S*?)\[0x([0-9a-f]+)\].*?\n\s*Summary: (.*)", body):
        res.append((int(m.group(2),16), m.group(1), m.group(3).strip()))
    for m in re.finditer(r"Address:\s+\(\)\s*\n\s*Summary:\s*$", body, re.M):
        res.append((None, "reexport", ""))
    return res

def file_word(p, segs, addr):
    for s in segs:
        va, fo, sz = hx(s.get("vmaddr") or s.get("vm_addr") or "0"), hx(s.get("fileoff") or s.get("file_offset") or "0"), hx(s.get("filesize") or s.get("file_size") or "0")
        if va <= addr < va+sz:
            with open(p,"rb") as f:
                f.seek(fo + (addr-va)); return struct.unpack("<Q", f.read(8))[0]
    return None

tot = {}
def bump(k, n=1): tot[k] = tot.get(k,0)+n

for name in [f for f in FIX if not os.environ.get("ORACLE_ONLY") or f==os.environ["ORACLE_ONLY"]]:
    p = os.path.join(CORP, name)
    dy = mj("dyld", p).get("dyld") or {}
    binds, rebases = [], []
    for f in (dy.get("chained_fixups") or {}).get("fixups") or []:
        (binds if f["kind"]=="bind" else rebases).append((hx(f["address"]), f.get("symbol"), f.get("target")))
    di = dy.get("dyld_info") or {}
    for f in (di.get("binds") or []) + (di.get("lazy_binds") or []): binds.append((hx(f["address"]), f["symbol"], None))
    for f in di.get("rebases") or []: rebases.append((hx(f["address"]), None, None))
    segs = mj("segments", p).get("segments") or []
    fns = [(hx(f["start"]), f["name"]) for f in (mj("functions", p).get("functions") or [])][:80]
    classes = []
    for c in (mj("objc", p).get("objc") or {}).get("classes") or []:
        ms = [(m["name"], hx(m["imp"]), False) for m in c.get("methods") or []][:40]
        ms += [(m["name"], hx(m["imp"]), True) for m in c.get("class_methods") or []][:40]
        classes.append((c["name"], ms))

    cmds = []
    for a,_,_ in binds+rebases: cmds.append(f"memory read -fx -s8 -c1 0x{a:x}")
    for a,_ in fns: cmds.append(f"image lookup -v -a 0x{a:x}")
    for cn, ms in classes:
        cmds.append(f'expr -l objc -- (void*)objc_getClass("{cn}")')
        for mn, imp, is_cls in ms:
            g = "class_getClassMethod" if is_cls else "class_getInstanceMethod"
            cmds.append(f'expr -l objc -- (void*)method_getImplementation((void*){g}((Class)objc_getClass("{cn}"), (SEL)sel_registerName("{mn}")))')
    out, bl = run_lldb(p, cmds)
    if "stop reason = breakpoint" not in out:
        m = re.search(r"error: (.*)", out); print(f"[{name}] SKIP: {m.group(1)[:90] if m else 'no main breakpoint'}"); continue
    slot = {}
    for a,_,_ in binds+rebases:
        b = bl.get(f"memory read -fx -s8 -c1 0x{a:x}","")
        m = re.search(r": 0x([0-9a-f]+)", b); slot[a] = int(m.group(1),16) if m else None
    # second pass A: symbolicate every distinct pointer
    ptrs = sorted({slot[a] for a,_,_ in binds if slot.get(a)})
    _, blA = run_lldb(p, [f"image lookup -a 0x{v:x}" for v in ptrs])
    at = {v: parse_lookup(blA.get(f"image lookup -a 0x{v:x}","")) for v in ptrs}
    # second pass B: name lookups ONLY for binds that did not already match by name (data symbols such as
    # __stack_chk_guard make both Apple's and Homebrew's lldb exit(1) on `image lookup -n`, killing the session)
    need = set()
    for a, sym, _ in binds:
        v = slot.get(a); hits = at.get(v) or [] if v else []
        disp = hits[0][2] if hits else ""; nm = disp.split("`")[-1] if "`" in disp else disp
        if nm != sym1(sym): need.add(sym1(sym))
    syms = sorted(need)
    _, bl2 = run_lldb(p, [f"image lookup -n {s}" for s in syms]) if syms else (None, {})
    byname = {s: parse_lookup(bl2.get(f"image lookup -n {s}","")) for s in syms}
    reexp = {s for s in syms if re.search(r"Address:\s*\(\)", bl2.get(f"image lookup -n {s}",""))}
    aborted = {s for s in syms if f"image lookup -n {s}" not in bl2}
    cat = {}; fails = []
    for a, sym, _ in binds:
        v = slot.get(a); s1 = sym1(sym)
        if v is None: cat["unreadable"]=cat.get("unreadable",0)+1; fails.append((hex(a),sym,"slot unreadable")); continue
        hits = at.get(v) or []; disp = hits[0][2] if hits else ""; unslid = hits[0][0] if hits else None
        nm = disp.split("`")[-1] if "`" in disp else disp
        cands = byname.get(s1) or []
        k = None
        if nm == s1: k = "exact"
        elif unslid is not None and any(c[0]==unslid for c in cands): k = "alias"
        elif s1 in reexp or any(c[0] is None for c in cands): k = "reexport"
        elif sym == "__tlv_bootstrap" and nm == "_tlv_get_addr": k = "tlv-rewrite"
        elif sym.startswith("_OBJC_CLASS_$_") and disp.endswith(": "+sym[len("_OBJC_CLASS_$_"):]): k = "objc-class"
        elif sym.startswith("_OBJC_METACLASS_$_") and disp.endswith(": "+sym[len("_OBJC_METACLASS_$_"):]): k = "objc-class"
        elif sym == "___CFConstantStringClassReference" and disp.endswith("__NSCFConstantString"): k = "objc-class"
        elif s1 in aborted: k = "lldb-aborted"; fails.append((hex(a), sym, f"lldb exited during name lookup; slot=0x{v:x} lldb='{disp[:50]}'"))
        else: k = "FAIL"; fails.append((hex(a), sym, f"slot=0x{v:x} lldb='{disp[:60]}'"))
        cat[k]=cat.get(k,0)+1; bump("bind:"+k)
    lazy_addrs = {a for a,_,_ in binds}
    sel_by_addr = {}
    for sdef in (mj("objc", p).get("objc") or {}).get("selectors") or []:
        try: sel_by_addr[hx(sdef["selref"])] = sdef["name"]
        except Exception: pass
    rcat = {}; pending_sel = []
    for a, _, target in rebases:
        v = slot.get(a)
        want = hx(target) if target and target!="0x0" else file_word(p, segs, a)
        if v is not None and want is not None and v == want: k="exact"
        elif a in lazy_addrs: k="bind-authoritative"   # slot also carries a (lazy) bind; dyld applies the bind last
        elif a in sel_by_addr and v: k="selref-uniqued"; pending_sel.append((a, v, sel_by_addr[a]))
        else: k="FAIL"; fails.append((hex(a),"rebase",f"slot={v and hex(v)} want={want and hex(want)}"))
        rcat[k]=rcat.get(k,0)+1
    if pending_sel:  # prove uniquing: the runtime pointer must name the same selector string machre decoded
        _, bl3 = run_lldb(p, [f"memory read -s1 -fc -c{len(n)+1} 0x{v:x}" for _,v,n in pending_sel])
        for a,v,n in pending_sel:
            b = bl3.get(f"memory read -s1 -fc -c{len(n)+1} 0x{v:x}","")
            got = "".join(re.findall(r"^0x[0-9a-f]+: (.*)$", b, re.M)).replace("\\0","")
            if got.strip() != n: rcat["selref-uniqued"]-=1; rcat["FAIL"]=rcat.get("FAIL",0)+1; fails.append((hex(a),"selref",f"machre={n!r} runtime={got!r}"))
    for k,n in rcat.items(): bump("rebase:"+k, n)
    rok = sum(n for k,n in rcat.items() if k!="FAIL"); rbad = rcat.get("FAIL",0)
    fok=fbad=0
    for a,n in fns:
        b = bl.get(f"image lookup -v -a 0x{a:x}","")
        m = re.search(r'range = \[0x([0-9a-f]+)-0x[0-9a-f]+\), name="([^"]*)"', b)
        if m and int(m.group(1),16)==a: fok+=1
        else: fbad+=1; fails.append((hex(a),"fn_start",n, (m.group(0)[:60] if m else "no symbol")))
    bump("fn:ok",fok); bump("fn:FAIL",fbad)
    cok=cbad=0
    for cn, ms in classes:
        b = bl.get(f'expr -l objc -- (void*)objc_getClass("{cn}")',""); m = re.search(r"= 0x([0-9a-f]+)", b)
        if m and int(m.group(1),16): cok+=1
        else: cbad+=1; fails.append(("objc-class",cn,"runtime has no such class"))
        for mn, imp, is_cls in ms:
            g = "class_getClassMethod" if is_cls else "class_getInstanceMethod"
            b = bl.get(f'expr -l objc -- (void*)method_getImplementation((void*){g}((Class)objc_getClass("{cn}"), (SEL)sel_registerName("{mn}")))',"")
            m = re.search(r"= 0x([0-9a-f]+)", b); got = int(m.group(1),16) if m else None
            if got == imp: cok+=1
            else: cbad+=1; fails.append(("objc-imp",f"{'+' if is_cls else '-'}[{cn} {mn}]",f"machre=0x{imp:x} runtime={got and hex(got)}"))
    bump("objc:ok",cok); bump("objc:FAIL",cbad)
    parts = [f"binds {sum(cat.values())} {dict(cat)}"] if binds else []
    if rebases: parts.append(f"rebases {rok}/{rok+rbad} {dict(rcat)}")
    if fns: parts.append(f"fn_starts {fok}/{fok+fbad}")
    if classes: parts.append(f"objc {cok}/{cok+cbad}")
    print(f"[{name}] " + "  ".join(parts))
    for f in fails[:8]: print("     ✗", f)
    if len(fails)>8: print(f"     … {len(fails)-8} more")
print("\nTOTAL", json.dumps(tot, sort_keys=True))
