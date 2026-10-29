# ASC-RS

ASC-RS is a Rust rewrite of the command-line core of
[Droid ASC](https://github.com/MG1937/ASC). It opens `classes*.dex` entries
directly from an APK, parses DEX metadata without Python, locates classes, and
scans bytecode references to strings, types, methods, and fields.

Java source rendering defaults to Androguard's pure-Rust `dex-decompiler`,
which builds on its Rust `dex-parser` and `dex-bytecode` projects. Binary
Android manifests are decoded by Androguard's Rust `axml-parser`. This default
path has no Python, JVM, JADX, or other external runtime dependency. An optional
JADX CLI backend is available when higher-level Java reconstruction is more
important than startup latency.

`getclass` follows ASC's on-demand pipeline rather than decompiling the whole
DEX:

1. Read root DEX metadata from the mapped ZIP central directory, then probe
   compressed-size-ordered DEX files with a type-table binary search until the
   requested class is found.
2. Walk only that class's instructions and collect string/type/field/method
   dependencies.
3. Preserve its interfaces, annotations, static values, debug metadata, and
   try/catch handlers.
4. Canonically sort and deduplicate every referenced ID table, then rewrite all
   instruction and metadata operands.
5. Build and validate a one-class DEX in memory, including section layout,
   SHA-1 signature, and Adler-32 checksum.
6. Pass that small DEX to the selected built-in or JADX decompiler.

The parser primitives used by reference search and minimal-DEX extraction live
in one shared format layer. A reusable `AscSession` owns mapped APK metadata, a
bounded LRU DEX cache, successful class locations, and its worker pool. Cached
entries retain parsed metadata, method descriptors, and per-reference-kind
bytecode indexes; repeated GUI/service queries therefore avoid reinflating,
reparsing, and walking the same instructions. Concurrent requests for the same
entry share one load. The bytecode walker reads little-endian code units directly
from the DEX buffer instead of allocating a temporary instruction vector for
every method.
Physical DEX 041 containers are exposed and searched as separate logical DEX
files while their absolute offsets continue to address one shared buffer.

## Build

```powershell
cargo build --release
```

The executable is `target/release/asc-rs.exe` on Windows.

## Codex Skill

The repository includes a discoverable Codex skill at
`.agents/skills/asc-rs`. Launch Codex anywhere inside this repository and invoke
`$asc-rs`, or describe a focused APK decompilation, reference-search, or
manifest task and let Codex select it automatically. The layout follows the
[official OpenAI skill format](https://learn.chatgpt.com/codex/build-skills).

## Usage

```powershell
asc-rs getclass app.apk com.example.Main -o Main.java
asc-rs getclass --engine jadx app.apk com.example.Main -o Main.java
asc-rs getclass --engine jadx --jadx-path C:\tools\jadx\bin\jadx.bat app.apk com.example.Main
asc-rs decompile-all app.apk
asc-rs decompile-all -m restructure -o sources app.apk
asc-rs findrefs app.apk string Authorization
asc-rs findrefs app.apk strings Authorization token api.example.com
asc-rs findrefs app.apk type com.example.Main
asc-rs findrefs app.apk method onCreate --class com.example.Main
asc-rs findrefs app.apk method notify --class openclaw --fuzzy-class
asc-rs findrefs app.apk field token --class com.example.Main
asc-rs manifest app.apk -o AndroidManifest.xml
asc-rs classes --contains MainActivity app.apk
asc-rs entries --contains assets/ app.apk
asc-rs entry --offset 1024 --length 64 --encoding hex app.apk assets/data.bin
asc-rs findrefs --format json app.apk string Authorization
```

Use `--debug` for per-DEX counts and timings, and `--threads N` to choose the
number of DEX inflation and search workers. `getclass` defaults to the in-process
pure-Rust `builtin` engine and its fast `simple` strategy. Use `--engine jadx`
for the external JADX CLI, which is usually slower to start but often produces
more readable Java. ASC-RS searches for JADX on `PATH`; `--jadx-path PATH` selects
an explicit executable or launcher. JADX defaults to `restructure`; both engines
accept explicit `-m restructure`, `-m simple`, and `-m fallback` overrides.

The `strings` form accepts one or more patterns and scans each DEX string table
once with a shared multi-pattern matcher. Its output stays grouped by query;
overlapping, repeated, and empty patterns have the same semantics as separate
`string` searches.

`decompile-all` is the whole-APK counterpart of `getclass`: it writes every
class as `<output>/<package path>/<Class>.java` using the built-in Rust engine
(`-o` selects the directory and defaults to the current directory). Standalone
DEX files are parsed once and their classes are split across the worker pool;
DEX 041 container sub-files reuse the per-class minimal-DEX rebuild. Classes
that fail to decompile are reported and skipped instead of aborting the run.
For a full JADX dump, run the JADX CLI directly on the APK.

Reference results include complete Dalvik method and field signatures. The
library's structured results additionally retain the caller and target indexes
and the exact code-unit offset for navigation.

The `classes` command provides lightweight class discovery across all root DEX
files. `entries` inventories the APK without extracting it, while `entry` reads
an exact uncompressed byte range as a hex dump, UTF-8 text, or an output-only
raw file. Every command supports `--format json` except raw entry output;
`--debug` diagnostics continue to use stderr.

## Library API

Frontends can keep one session open and receive structured results:

```rust
use asc_rs::{
    apk::{list_entries, read_entry_range},
    dex::Query,
    service::{
        AscSession, DecompilationEngine, DecompilationMode, DecompileOptions,
    },
};

let session = AscSession::open("app.apk", 8)?;
let class = session.decompile_class(
    "com.example.Main",
    DecompilationMode::Simple,
)?;
let jadx_class = session.decompile_class_with_options(
    "com.example.Main",
    &DecompileOptions {
        engine: DecompilationEngine::Jadx,
        mode: DecompilationMode::Restructure,
        jadx_executable: None,
    },
)?;
let references = session.find_references(
    &Query::String("Authorization".to_owned()),
)?;
let dump = session.decompile_all(
    std::path::Path::new("sources"),
    DecompilationMode::Simple,
)?;
let batch = session.find_string_references_batch(&[
    "Authorization".to_owned(),
    "token".to_owned(),
])?;
let classes = session.apk().list_classes()?;
let entries = list_entries(std::path::Path::new("app.apk"))?;
let bytes = read_entry_range(
    std::path::Path::new("app.apk"),
    "assets/data.bin",
    1024,
    Some(64),
)?;
# Ok::<(), anyhow::Error>(())
```

`OperationObserver` provides thread-safe progress and cancellation callbacks.
The default session cache owns at most 512 MiB of decompressed DEX data; parsed
metadata and lazy indexes are evicted with their owning DEX. Use
`AscSession::open_with_cache_limit` to choose another bound, and
`ApkSession::clear_dex_cache` to explicitly release all cached entries.

See [`BENCHMARK.md`](BENCHMARK.md) for the speed and result-set comparison
against the original Python ASC on the supplied demo APK.
