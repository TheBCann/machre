# machre JSON schema (schema 1)

Normative key inventory for every `--json` / `--json-compact` document (DESIGN.md §6). The envelope is
identical for every command; the per-command payload lives under the command's own name. The golden
`json_keys` rows in `tests/golden/*.rows.zig` check the listed keys against real output, and
`tests/facts/triage.zig` checks that this file names every command, every triage rule id and every exit
code — so the document cannot drift away from the tool.

Reading order: [Envelope](#envelope) → [Conventions](#conventions) → [Per-command payloads](#per-command-payloads)
→ [Triage rule ids](#triage-rule-ids) → [Exit codes](#exit-codes).

## Envelope

```json
{ "machre": { "version": "0.1.0", "schema": 1, "command": "info", "capstone": true, "security": true },
  "file": { "path": "tests/corpus/hello-c", "size": 50424,
            "sha256": "a448ac67…b15c5", "mtime": "2026-09-11T23:47:02Z", "mtime_unix": 1789000022,
            "container": "thin", "fat": null,
            "xattrs": [], "quarantine": null, "translocated": false },
  "arches": [ { "arch": "arm64", "index": 0, "offset_in_file": 0, "size": 50424,
                "cputype": "0x100000c", "cpusubtype": "0x0", "caps": "0x0", "valid": true,
                "<command>": { "…payload…": 0 } } ],
  "diagnostics": [ { "severity": "warning", "module": "loadcmds", "code": "cmdsize_invalid", "offset": 32, "message": "…" } ],
  "diagnostics_dropped": 0,
  "exit_code": 0 }
```

| key | type | notes |
|---|---|---|
| `machre.version` | string | build option `version` |
| `machre.schema` | number | bumped only on incompatible changes |
| `machre.command` | string | canonical command name (aliases resolved) |
| `machre.capstone`, `machre.security` | bool | compiled-in features (`build_options.have_*`) |
| `file.path` | string | as given on the command line, sanitised (`path_hex`/`path_lossy` siblings when bytes were replaced) |
| `sanitized_strings` | number | file-derived strings that contained control characters or invalid UTF-8 and were escaped/replaced on their way out (0 for a clean file); a `cli.invalid_utf8` warning carries the same count |
| `file.size` | number | bytes on disk (0 for directories) |
| `file.sha256` | string \| null | lowercase hex, null for directories or unreadable files |
| `file.mtime`, `file.mtime_unix` | string, number | ISO-8601 UTC + unix seconds |
| `file.container` | string | `thin` \| `fat` \| `not_macho` \| `bundle` |
| `file.fat` | object \| null | `{magic, nfat_arch, arches[{arch,cputype,cpusubtype,offset,size,align,valid}]}` — every declared slice, even when `--arch` selected one |
| `file.xattrs`, `file.quarantine`, `file.translocated` | array, object \| null, bool | file properties (a bundle path keeps the properties of the path the user named) |
| `arches` | array | always an array: one element for thin, N for `--all-archs` (the JSON default), exactly one for `--arch`, empty for non-Mach-O input |
| `arches[i].arch` … `caps` | string | `Arch.displayName`, hex strings for cputype/cpusubtype/caps |
| `arches[i].<command>` | object | the command payload, keyed by the command name; `{"available": false, "reason": "…"}` when a feature is compiled out or disabled by a flag |
| `bundle`, `plist`, `quarantine`, `triage`, `spctl`, `version` | object | top-level payloads written by the commands that produce them (absent otherwise) |
| `diagnostics[]` | array | `{severity: info\|warning\|error, module, code, offset: number\|null, message}`; `module`/`code` are the `core/diag.zig` enum tag names |
| `diagnostics_dropped` | number | diagnostics lost to `max_diagnostics` or OOM |
| `exit_code` | number | the process exit code, echoed so a pipeline can consume either channel |

## Conventions

* Addresses, vm offsets, raw pointers, addends, magics, flag values and cputypes are lowercase `"0x…"`
  strings (`Hex64`); sizes, counts, file offsets, indices and ordinals are JSON numbers (all < 2^53). Any
  `u64` that might exceed 2^53 is emitted as a hex string, never a bare number (`json.int`).
* Digests are lowercase hex without `0x` (`HexBytes`). UUIDs are upper-case `8-4-4-4-12`. Times are ISO-8601
  UTC strings with `<key>_unix` siblings where the source was numeric.
* Every file-derived string goes through `json.str`: invalid UTF-8 and C0 controls (except `\t\n\r`) become
  U+FFFD; whenever a replacement happened the object also carries `<key>_hex` (original bytes) and
  `<key>_lossy: true`. `std.json.Stringify` therefore never falls into its number-array form.
* Enum-like values are lowercase snake strings; flag sets are `{"value":"0x200085","names":["NOUNDEFS", …]}`
  in the reference tool's spelling (`_full` variants use the summary.json spelling, e.g. `MH_NOUNDEFS`).
* Optional data that is absent is `null`; absent *features* are `{"available": false, "reason": "…"}` so
  "unsigned" and "not checked" stay distinguishable.
* `--limit` cuts carry `"truncated": true, "total": N` next to the array.
* The document is always closed: on an internal error the envelope ends with `"exit_code": 70` and an
  error diagnostic (`json.closeAll` unwinds any half-written containers).
* A key is never emitted twice in the same object. `report` merges several commands into one envelope and
  resolves a collision by ownership: the command named like the key wins (`entropy` over the `entropy`
  object `segments --entropy` also emits), otherwise the first section that produced it.

## Per-command payloads

Every heading below is the value of `arches[i].<command>` unless it says *top level*.

### `info`

`header{magic,magic_name,cputype,cputype_name,cpusubtype,cpusubtype_low,caps,filetype,filetype_name,ncmds,sizeofcmds,flags{value,names},flags_full,is_64,endian}`,
`uuid`, `build_version{platform,platform_name,minos,sdk,tools[{tool,name,version}]}`, `version_min{cmd,version,sdk}`,
`source_version`, `dylinker`, `entry{kind,entryoff,address,stacksize,symbol}`,
`dyld{style,pointer_formats[],imports,fixups,exports,function_starts,chained_fixups_cmd,exports_trie_cmd}`,
`dylibs[{ordinal,cmd,path,short_name,current_version,compatibility_version,timestamp,weak,reexport,upward,delayed_init}]`,
`id_dylib`, `rpaths[]`,
`segments[{name,vmaddr,vmsize,fileoff,filesize,maxprot,initprot,nsects,flags{value,names},file_range_truncated,entropy,file_fraction,sections[…]}]`
(`entropy`/`file_fraction` are `null` unless the command computed them),
`symbols{total,defined,undefined,stabs,external,local,indirect}`, `symtab{symoff,nsyms,stroff,strsize}`,
`code_signature{present,flags{value,names},identifier,team_id,cdhash,hash_type,pages_ok,pages_total,page_mismatches}`,
`security{available,trust,status,status_name,notarized}`, `encryption{cryptoff,cryptsize,cryptid}|null`.

### `header`

`header{header{…as info…}, fat{nfat_arch,slices}|null}`.

### `loadcmds`

`loadcmds{ncmds_parsed, truncated, load_commands[{index,cmd,cmd_value,cmdsize,offset,requires_dyld, …typed fields
per LC; segments carry `sections[]`; unknown commands carry `raw_hex`}]}`.

### `segments`

`segments[{…as info…, sections[{index,sectname,segname,addr,size,offset,align,reloff,nreloc,
flags{value,type,type_name,attrs[]},reserved1,reserved2,reserved3,class,entropy}], section_count}]`, plus a
sibling `entropy{file,segments[]}` with `--entropy` and `{"available":false,"reason":"not requested (--entropy)"}`
without it. The per-segment `entropy`/`file_fraction` and per-section `entropy` keys are always emitted and
are `null` unless `--entropy` was given.

### `symbols`

`symtab{symoff,nsyms,stroff,strsize}`,
`dysymtab{ilocalsym,nlocalsym,iextdefsym,nextdefsym,iundefsym,nundefsym,tocoff,ntoc,modtaboff,nmodtab,extrefsymoff,nextrefsyms,indirectsymoff,nindirectsyms,extreloff,nextrel,locreloff,nlocrel}`,
`counts{defined,undefined,stabs,external,local}`,
`symbols[{index,name,nm,type,type_raw,sect,desc,value,external,private_external,weak_ref,weak_def,library_ordinal,library,stab}]`,
`indirect[{index,symbol_index,symbol,section}]`, `lossy_strings`.

### `dyld`

`source`, `chained_fixups{header{fixups_version,starts_offset,imports_offset,symbols_offset,imports_count,imports_format,symbols_format},
imports[{index,lib_ordinal,library,weak,name,addend}],
starts[{seg_index,segment,page_size,pointer_format,pointer_format_name,segment_offset,page_count,page_starts[]}],
fixups[{address,segment,section,kind,target,symbol,library,addend,auth{key,diversity,addr_div},raw}]}`,
`dyld_info{cmd{rebase_off,rebase_size,bind_off,bind_size,weak_bind_off,weak_bind_size,lazy_bind_off,lazy_bind_size,export_off,export_size},
rebases[{segment_index,segment_offset,address,type,stream_offset}],
binds[{segment_index,segment_offset,address,symbol,library_ordinal,library,addend,type,weak_import,stream_offset}],
weak_binds[…as binds…], lazy_binds[…as binds…], threaded}`,
`exports_trie{dataoff,datasize,count}`, `function_starts{dataoff,datasize,addresses[]}`,
`data_in_code{dataoff,datasize,entries[{offset,length,kind,kind_name}]}`.

### `imports`

`imports[{symbol,library,ordinal,weak,lazy,locations,first_location,source}]`, `dylibs[…]`, `rpaths[]`,
`resolution[{path,status,resolved,via_rpath,weak}]` or `resolution:{available:false}`.

### `exports`

`exports[{name,address,offset,kind,weak,reexport{ordinal,library,name},resolver}]`, `source`.

### `codesign`

`code_signature{present,dataoff,datasize,truncated,superblob{magic,magic_name,length,count,slots[{type,type_name,offset,magic,magic_name,length}]},
code_directories[{slot,version,flags{value,names},flags_full{value,names},hash_type,hash_type_name,hash_size,page_size,platform,
n_code_slots,n_special_slots,code_limit,exec_seg{base,limit,flags{value,names}},runtime,identifier,team_id,cdhash,cdhash_full,
special_slots[{slot,name,hash,bound,verified}],pages{checked,ok,mismatches,first_bad,code_limit_within_slice}}],
best_cdhash, requirements[{type,type_name,text,ops}], designated_requirement{text,synthesized},
entitlements{…as the `entitlements` command…}, cms{certificates[{subject{cn,ou,o,c,uid},issuer{cn,ou,o,c,uid},serial,
not_before,not_after,self_signed,sha256,marker_oids[]}],authority[],signing_time,has_timestamp,digest_algorithm,
signer_count,ber_indefinite}, offline_trust}`,
`security{available,evaluated_path,create_status,validity_status,validity_status_name,revocation_checked,
requirements{anchor_apple,apple_generic,developer_id,app_store,notarized},trust,identifier,team_id,format,flags,
signing_time,certificate_chain[],designated_requirement,stapled_ticket{present,length},elapsed_ms}`
or `{"available":false,"reason":"…"}`,
`verdict{signed,valid,trust,summary}`.

`security` is the `codesign` command's projection of `darwin/security.zig`, not the whole struct: the
verdict's `platform_identifier`, `runtime_version`, `cdhash`, `cdhashes[]`, `main_executable`,
`secure_timestamp`, `digest_algorithms[]`, `network_used` and `entitlements` fields are **not** serialised
here (`cmd/codesign.zig:592-625`). The `bundle` command emits its own, differently shaped `security` object
— see [`bundle`](#bundle).

### `entitlements`

`entitlements{source,keys[],xml,der,xml_raw?,der_length,disagreement,dangerous[{key,why,weight}]}`.

### `objc`

`objc{present,image_info{version,flags,swift_unstable,swift_stable,has_category_class_properties,is_swift},
classes[{address,name,superclass{kind,address,name},meta,swift,ro_flags{value,names},instance_start,instance_size,
methods[{name,types,imp,class_method,small}],class_methods[…as methods…],ivars[{name,type,offset,alignment,size}],
properties[{name,attributes}],protocols[]}],
categories[{address,name,class_name,class_external,instance_methods[],class_methods[],protocols[],properties[]}],
protocols[{address,name,protocols[],instance_methods[],class_methods[],optional_instance_methods[],optional_class_methods[]}],
selectors[{selref,name}],classrefs[{ref,name,external}],stubs[{address,selector}],truncated}`.

Instance and class methods are separate arrays on a class (`methods` / `class_methods`); each entry still
carries the `class_method` flag, plus `small` for the relative-method-list encoding.

### `strings`

`strings[{address,offset,section,kind,class,text,text_hex?,length,cut,lossy}]`, `total`, `lossy_strings`.

### `entropy`

`entropy{file,segments[{name,offset,size,entropy,file_fraction}],sections[{segment,section,offset,size,entropy,file_fraction}],
tells[{code,detail,weight}]}`.

### `plist`

*Top level.* `plist{format,detected_format,source,path,size,value}`. `plist.Value` JSON form: `<data>` →
`{"$data":"hex"}`, dates → ISO-8601, uid → `{"$uid":n}`.

### `bundle`

*Top level.* `bundle{root,kind,identifier,executable,executable_path,package_type,version,short_version,min_system,
ui_element,background_only,ats_arbitrary_loads,usage_descriptions[],url_schemes[],principal_class,
info_plist{format,path,entries,value},frameworks[],helpers[],xpc_services[],plugins[],dylibs[],
nested[{path,kind,executable,sealed_cdhash,sealed_requirement,actual_cdhash,cdhash_arch,matched_arch,cdhash_match,signed,arches[]}],
code_resources{version,rules,rules2,active_rules,files[{path,hash1,hash2,optional,symlink}],
nested[{path,cdhash,requirement}],verify{checked,mismatched[],missing[],unsealed[],ok}},
stapled_ticket{present,path,length},provisioning_profile,file_count,total_size,entries_walked,truncated,
security{available,reason,evaluated_path,status,status_name,trust,identifier,team_id,format,cdhash,stapled_ticket},
spctl{exit,assessment,source,origin}|{available:false}}`.

`code_resources.files[]` holds only the sealed resources that are *not* code; a sealed nested code object
moves to `code_resources.nested[]` (`cmd/bundle.zig:269-292`). There is no `active_files` key. `bundle`'s
`security` object is a different projection from the one `codesign` emits — it has `status`/`status_name`
and `cdhash` and omits the requirement-result block.

### `quarantine`

*Top level.* `xattrs[]`, `quarantine{raw,flags,timestamp,timestamp_unix,agent,uuid,well_formed}|null`,
`translocated`, `provenance`.

### `disasm`

`disasm{backend,text_backend,syntax,partial,functions[{name,start,end,source,
instructions[{address,size,bytes,mnemonic,operands,kind,target,comment,comment_kind,label,valid}]}],disagreements,truncated}`.

`instructions[].valid` is `false` for a word the decoder could not name (printed `.inst 0x…` on arm64,
`db 0x..` on x86_64, `kind: "invalid"`); a `.long` jump-table record is `valid: true` with `kind: "data"`
and a resolved `target`. DESIGN.md §5.6(d): the two spellings are deliberately distinct and must not be
collapsed.

### `functions`

`functions[{name,start,end,size,source,name_source,section}]`.

### `xrefs`

`xrefs[{from,from_function,to,to_name,kind,via_stub}]`, `pointer_slots_included`.

### `dump`

`dump{segment,section,address,offset,length,zerofill,vm_size,hex,ascii}`.

### `triage`

Emitted **per arch** (`arches[i].triage`) **and** merged at the top level (`triage`). The merged report is
the union of the per-slice findings with the worst level; its `summary.arch` joins the slice names
(`"x86_64+arm64"`).

```json
"triage": {
  "score": 60,
  "level": "suspicious",
  "categories_hit": ["signature", "packing"],
  "findings": [ { "id": "sig.invalid", "category": "signature", "severity": "high",
                  "weight": 35, "score": 35, "title": "signature does not match the file",
                  "detail": "…1/13 page hashes mismatch…", "evidence": [],
                  "corroborates": "pack.names" } ],
  "positives": [ { "id": "platform", "text": "Apple platform binary (anchor apple)", "credit": 20 } ],
  "corroboration": [ "packing tell (UPX_DATA) is corroborated by a broken signature -> file was modified after linking." ],
  "not_flagged": [ "entropy (max 5.16 __LINKEDIT)", "imports present (6)", "symbols present (12)",
                   "no quarantine xattr", "PIE", "no RWX segment" ],
  "summary": { "signed": true, "trust": "INVALID SIGNATURE", "notarized": false,
               "hardened_runtime": false, "quarantined": false, "packed_hint": true, "encrypted": false,
               "imports": 6, "exports": 5, "symbols": 12, "dylibs": 1, "objc_classes": 0, "arch": "arm64" },
  "exit_code": 0 }
```

| key | type | notes |
|---|---|---|
| `score` | number | `sum(findings[].score) - sum(positives[].credit)`, floored at 0 |
| `level` | string | `clean` (< 20) \| `notable` (20–49) \| `suspicious` (50–99) \| `likely_malicious` (>= 100); `suspicious` and above additionally require `categories_hit.length >= 2`, else the level drops one rung |
| `categories_hit[]` | array of string | distinct categories of the findings that actually **score**; a weight-0 finding is reported but never helps a file across the two-category gate |
| `findings[].id` | string | stable rule id from the table below; never renamed |
| `findings[].category` | string | `signature` \| `packing` \| `dependencies` \| `header` \| `entitlements` \| `strings` \| `objc` \| `bundle` \| `quarantine` \| `symbols` \| `structure` |
| `findings[].severity` | string | `info` \| `low` \| `medium` \| `high` (the sort key; ties break on weight) |
| `findings[].weight` | number | the rule's table weight, always < 50 (comptime-asserted: no single tell is a verdict) |
| `findings[].score` | number | what this occurrence contributed; `<= weight`, and 0 when the evidence is already counted elsewhere (`sig.adhoc` under a broken signature) or the rule is informational |
| `findings[].detail` | string | the concrete observation, sanitised |
| `findings[].evidence[]` | array of string | supporting lines, sanitised; may be empty |
| `findings[].corroborates` | string \| null | id of another finding this one supports |
| `positives[]` | array | negative evidence that subtracts: `{id,text,credit}` — `platform` 20, `notarized` 15, `app_store` 15, `hardened_runtime` 3 |
| `corroboration[]` | array of string | human sentences for finding pairs that reinforce each other |
| `not_flagged[]` | array of string | the negative facts an analyst should see next to the findings |
| `summary` | object | `signed`, `trust`, `notarized` (null when Security was not consulted), `hardened_runtime`, `quarantined`, `packed_hint`, `encrypted`, `imports`, `exports`, `symbols`, `dylibs`, `objc_classes`, `arch` |
| `exit_code` | number | 20 once `--fail-on=<level>` is reached, else 0 |

### `report`

*Per arch and top level.* Every payload above under its own command name: `arches[i]` carries the per-arch
payloads of the selected sections and the top-level payloads sit next to `arches`. `--only=<cmd,cmd,…>`
selects sections by command name or alias; `disasm` and `xrefs` are selectable but not in the default
document (they are unbounded listings), and `dump` is not a section at all (it needs its own selector).
The JSON default is every other command; text renders `info` + `codesign` + `imports` + `triage`.

### `version`

*Top level.* `version{machre,zig,capstone{available,version},security{available},host}`.

## Triage rule ids

Stable ids: an id is added, never renamed or reused. `weight` is the table weight; the emitted `score` may
be lower (see `findings[].score`). Every weight is below 50 by construction, so no single rule can reach
`suspicious` on its own.

| id | category | severity | weight | what it means |
|---|---|---|---|---|
| `sig.unsigned` | signature | high | 25 | no LC_CODE_SIGNATURE at all |
| `sig.adhoc` | signature | low | 10 | ad hoc signature (3 when linker-signed, 0 when already invalid) |
| `sig.invalid` | signature | high | 35 | a page hash or Security.framework disagrees with the CodeDirectory |
| `sig.revoked` | signature | high | 45 | revoked certificate or notarization |
| `sig.devid_not_notarized` | signature | medium | 15 | Developer ID that was never notarized |
| `sig.not_evaluated` | signature | info | 0 | `--no-security` or a build without Security.framework |
| `sig.sha1_only` | signature | medium | 8 | no SHA-256 CodeDirectory |
| `sig.hardened_runtime_missing` | signature | low | 8 | certificate-signed without CS_RUNTIME |
| `pack.entropy` | packing | medium | 25 | segment above 7.0 bits/byte over more than 20% of the slice |
| `pack.names` | packing | medium | 25 | known packer segment/section name (`__XHDR`, `UPX_DATA`, `upxTEXT`, `__MPRESS__`) |
| `pack.no_imports_no_symbols` | packing | medium | 25 | imports nothing and exports nothing |
| `pack.protected_segment` | packing | medium | 20 | `SG_PROTECTED_VERSION_1` |
| `pack.encryption_info` | packing | medium | 20 | `LC_ENCRYPTION_INFO*` with `cryptid != 0` |
| `pack.tiny_text_large_data` | packing | low | 8 | far more data than code |
| `deps.missing_dylib` | dependencies | high | 20 | a dependency is neither on disk nor in the shared cache |
| `deps.rpath_frameworks` | dependencies | low | 5 | `LC_RPATH` absolute path outside the system frameworks |
| `deps.reexport` | dependencies | medium | 10 | `LC_REEXPORT_DYLIB` (proxy/shim shape) |
| `deps.dyld_environment` | dependencies | high | 20 | `LC_DYLD_ENVIRONMENT` |
| `deps.weak_unusual` | dependencies | low | 3 | weak dependency on a non-system library |
| `hdr.rwx_segment` | header | high | 30 | segment mapped writable and executable |
| `hdr.rwx_maxprot` | header | medium | 15 | segment is r-x but maxprot permits rwx, so it may be re-protected writable and rewritten in place (2 of 1178 system/app binaries) |
| `hdr.allow_stack_execution` | header | high | 20 | `MH_ALLOW_STACK_EXECUTION` |
| `hdr.no_pie` | header | low | 8 | executable without `MH_PIE` |
| `hdr.unknown_lc_req_dyld` | header | high | 20 | unknown load command carrying `LC_REQ_DYLD` |
| `hdr.unknown_lc` | header | low | 5 | unknown load command |
| `hdr.segment_order` | header | low | 5 | `__LINKEDIT` is not the last segment |
| `hdr.text_not_at_zero` | header | low | 5 | `__TEXT` does not start at file offset 0 |
| `hdr.unixthread_entry` | header | low | 8 | `LC_UNIXTHREAD` entry point instead of `LC_MAIN` |
| `hdr.entry_outside_text` | header | medium | 20 | entry point outside the executable segment |
| `ent.get_task_allow` | entitlements | medium | 10 | `com.apple.security.get-task-allow` |
| `ent.disable_library_validation` | entitlements | medium | 12 | `com.apple.security.cs.disable-library-validation` |
| `ent.allow_jit` | entitlements | low | 8 | `com.apple.security.cs.allow-jit` |
| `ent.allow_unsigned_memory` | entitlements | medium | 12 | `com.apple.security.cs.allow-unsigned-executable-memory` |
| `ent.allow_dyld_env` | entitlements | medium | 12 | `com.apple.security.cs.allow-dyld-environment-variables` |
| `ent.debugger` | entitlements | medium | 10 | `com.apple.security.cs.debugger` |
| `ent.xml_der_mismatch` | entitlements | high | 20 | the XML and DER entitlement blobs disagree |
| `str.script_interpreters` | strings | medium | 8 | shell/interpreter strings |
| `str.persistence_paths` | strings | medium | 10 | LaunchAgents/LaunchDaemons/keychain paths |
| `str.network_indicators` | strings | low | 5 | embedded URLs or literal IP addresses |
| `str.base64_blobs` | strings | low | 5 | long base64-looking strings |
| `str.anti_analysis` | strings | medium | 10 | debugger/VM/analysis-tool names |
| `objc.suspicious_selectors` | objc | medium | 8 | keychain, screen capture, AppleScript, task spawning or accessibility selectors |
| `sym.stripped` | symbols | info | 0 | no local symbols |
| `stubs.mismatch` | structure | medium | 15 | a stub loads a symbol the indirect symbol table does not name |
| `bundle.no_info_plist` | bundle | high | 20 | bundle directory without an Info.plist |
| `bundle.executable_mismatch` | bundle | high | 20 | `CFBundleExecutable` is missing or does not match |
| `bundle.nested_unsigned` | bundle | medium | 15 | unsigned nested code object |
| `bundle.resource_mismatch` | bundle | high | 25 | a sealed resource hash does not match |
| `bundle.unsealed` | bundle | medium | 10 | files inside the bundle that CodeResources does not cover |
| `bundle.ui_element` | bundle | low | 3 | `LSUIElement` / `LSBackgroundOnly` |
| `bundle.ats_insecure` | bundle | low | 5 | `NSAllowsArbitraryLoads` |
| `quarantine.present` | quarantine | info | 0 | `com.apple.quarantine` xattr (provenance, not a defect) |
| `quarantine.translocated` | quarantine | info | 0 | running from an App Translocation copy |
| `diag.malformed` | structure | medium | 10 | a Mach-O parser recorded an error-severity diagnostic |

## Exit codes

Echoed as `exit_code` in the envelope and returned by the process.

| code | meaning |
|---|---|
| `0` | success (diagnostics may have been printed) |
| `1` | usage error (unknown command/flag, bad value, missing path) |
| `2` | file not found / permission denied / I/O error |
| `3` | not a Mach-O and the command needs one; `--arch` not present; fat file with no valid slice |
| `4` | `--strict` and at least one error-severity diagnostic |
| `5` | input exceeds `--max-file-size`, or a limit made the analysis incomplete under `--strict` |
| `6` | feature unavailable (`--backend=capstone` without Capstone; `--spctl` off macOS) |
| `20` | `triage --fail-on` threshold reached |
| `70` | internal error (OOM past the arena budget); the JSON envelope is still closed |
