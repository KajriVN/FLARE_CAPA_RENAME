# capa auto-rename for IDA Pro

Renames functions from capa rule matches, so you don't have to rename each `sub_...` by hand
after reading capa explorer's results.

```
sub_1400068D4  ->  capa_enumerate_services            [HIGH]  enumerate services
sub_14001240C  ->  capa_parse_PE_header               [HIGH]  parse PE header
sub_140001B80  ->  capa_acquire_debug_privileges      [MEDIUM] acquire debug privileges (also: modify access privileges)
sub_14000C340  ->  capa_terminate_process             [LOW]   large function (41 basic blocks, 43 calls)
```

It reuses capa explorer's analysis: results cached in the database by capa explorer are used directly,
otherwise capa runs once and writes that cache. The capa rules directory setting is shared with capa explorer.

## Installation

The plugin is the Python package `capa_rename` (this directory), built on top of the `flare-capa` package.

1. Install this repository into the Python environment IDA uses: `pip install -e <path to this repository>`.
   This also installs `flare-capa` 10 if it is missing.
2. Copy [capa_renamer.py](capa_renamer.py) into your IDA plugins directory
   (Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins`).
3. Get the [capa rules](https://github.com/mandiant/capa-rules/releases) matching your capa version
   and select them in the plugin settings (or in capa explorer: the setting is shared).

Tests: `python -m pytest tests` (set `CAPA_RULES` to a rules directory to also check every rule name).

## Usage

- Edit > Plugins > FLARE capa auto-rename (`Alt-Shift-F5`) shows one proposal per function.
  Gray rows will not be renamed; the Status and Why columns say why. Double click to jump to a function.
- Right click in the list:
  - **Rename selected** (`Ctrl-Enter`)
  - **rename all >= min confidence**: renames every eligible function at or above the configured confidence (HIGH by default)
  - **Undo selected** / **undo all**
  - **Re-run capa**, **settings**
- "rename all", "undo all" and "settings" are also in the Edit > Plugins menu.

## How a name is chosen

For each function:

1. collect the capability rules that matched in it (function, basic block and instruction scope;
   library, internal and file scope rules are ignored),
2. drop rules that another matched rule depends on through `match:` (keep "inject dll", drop "write process memory"),
3. treat "reference ...", "contain ...", packer/compiler/linker rules and a few known incidental rules as weak evidence,
4. pick the best remaining rule (basic block/instruction evidence first, then the more specific namespace),
5. grade the confidence:
   - HIGH: one strong capability
   - MEDIUM: up to three related capabilities (same namespace family)
   - LOW: unrelated capabilities, or only weak evidence
   - large functions (more than 40 basic blocks or 20 calls by default) are downgraded one level, two levels above twice that.

The name is derived from the rule name, deterministically: platform qualifiers ("on Linux", "in .NET")
and filler words are dropped, the rest is transliterated to ASCII and joined:

| rule | name |
|---|---|
| `check for time delay via QueryPerformanceCounter` | `capa_check_time_delay_QueryPerformanceCounter` |
| `encrypt data using HC-128 via WolfSSL` | `capa_encrypt_data_HC_128_WolfSSL` |
| `use process Doppelgänging` | `capa_use_process_Doppelganging` |

Every name matches `^[A-Za-z_][A-Za-z0-9_]*$`, avoids C/C++ keywords and IDA dummy name patterns (`sub_...`),
and is made unique with a `_2`, `_3`, ... suffix. Styles: `snake` (default), `lower`, `pascal`.

## Safety

- only functions with an auto-generated name (`sub_...`), or a name set by this plugin earlier, are renamed;
  library (FLIRT) functions, thunks and names from users, Lumina or debug symbols are kept,
  unless "Also rename functions that already have a name" is set or you select them explicitly.
- the previous names are stored in the database, so undo works across sessions.
  undo leaves a function alone if you renamed it by hand after the capa rename.
- an optional function comment lists the matched rules; undo removes it and keeps the rest of the comment.

## Rule name overrides

A YAML or JSON file mapping rule names to function names, or to `null` to ignore a rule that produces
false positives on your samples. See [rename-overrides.example.yml](rename-overrides.example.yml).

## Scripting (idat, idalib)

```python
import capa_rename.ida_backend as rb

proposals = rb.auto_rename(min_confidence="HIGH", dry_run=True)
print(rb.format_report(proposals))
rb.auto_rename(min_confidence="HIGH")
rb.undo()
```

## Limitations

The names are only as good as the rule matches. capa tells you that a function contains a behavior, not that
the behavior is the function's purpose, so some names will be wrong. In a test on two Windows binaries with
symbols (comparing proposals against the real names), 16 of 25 HIGH proposals were right, 4 partially right
and 5 wrong; most wrong ones were C runtime functions (normally recognized by FLIRT and skipped)
and a rule whose name is broader than what it matches. Use the preview, keep the prefix, and use the
override file to silence rules that mislead on your samples.
