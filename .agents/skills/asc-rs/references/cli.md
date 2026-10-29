# ASC-RS CLI reference

## Resolve the executable

When working in the ASC-RS source repository, use the release binary if it is
current:

- Windows: `.\target\release\asc-rs.exe`
- Linux/macOS: `./target/release/asc-rs`

Run `cargo build --release` when the binary is missing or the task requires the
current source changes. Outside the repository, use `asc-rs` from `PATH` or a
user-provided executable path. Never invent an executable or APK path.

In the forms below, replace `<asc>` with the resolved executable and quote all
paths or values that contain spaces or shell metacharacters. Put `getclass` and
`findrefs` parent options before the APK path; in particular, a trailing
`--debug` after a `findrefs` query is parsed as a query argument.

## Decompile one class

```text
<asc> getclass [--debug] [--threads N] [-o FILE] \
  [--format text|json] [--engine builtin|jadx] [--jadx-path PATH] \
  [-m restructure|simple|fallback] APK CLASS
```

`CLASS` accepts `com.example.Main` or `Lcom/example/Main;`.

- `builtin` is the default engine and defaults to `simple` mode.
- `jadx` defaults to `restructure`. It searches common `jadx` launchers on
  `PATH`; use `--jadx-path` only with this engine.
- `-o` writes the source and the command also prints it to stdout.
- `--threads` controls APK/DEX work; external JADX decompiles the rebuilt
  one-class DEX with one worker.

Examples:

```powershell
<asc> getclass app.apk com.example.Main
<asc> getclass --engine builtin -m restructure -o Main.java app.apk com.example.Main
<asc> getclass --engine jadx -o Main.java app.apk com.example.Main
<asc> getclass --engine jadx --jadx-path C:\tools\jadx\bin\jadx.bat app.apk com.example.Main
```

## Decompile every class

```text
<asc> decompile-all [--debug] [--threads N] [--format text|json] \
  [-m restructure|simple|fallback] [-o DIR] APK
```

Writes the whole APK as a Java source tree using the built-in Rust engine
(there is no `--engine` option; for a JADX full dump run `jadx` directly).
`-o DIR` selects the output directory and defaults to the current directory.
Each class lands at `DIR/<package path>/<Class>.java`; `simple` is the default
mode. Standalone DEX files are parsed once and decompiled in parallel; DEX 041
container sub-files go through the same minimal-DEX rebuild as `getclass`.
Classes that fail to decompile are reported individually and skipped instead
of aborting the run.

```powershell
<asc> decompile-all -o sources app.apk
<asc> decompile-all -m restructure -o sources app.apk
```

## Find bytecode references

Parent options are `--debug`, `--threads N`, `--format text|json`, and
`-o FILE`:

```text
<asc> findrefs [--debug] [--threads N] [-o FILE] APK string VALUE
<asc> findrefs [--debug] [--threads N] [-o FILE] APK strings VALUE...
<asc> findrefs [--debug] [--threads N] [-o FILE] APK type VALUE
<asc> findrefs [--debug] [--threads N] [-o FILE] APK method [NAME] [--class CLASS] [--fuzzy-class]
<asc> findrefs [--debug] [--threads N] [-o FILE] APK field [NAME] [--class CLASS] [--fuzzy-class]
```

Semantics:

- `string` and `strings` match substrings of DEX string constants.
- `type` matches a descriptor substring; Java dots in the query are normalized
  to slashes.
- Method and field `NAME` values are substring matches. At least `NAME` or
  `--class` is required.
- `--class` is an exact Java name or Dalvik descriptor by default.
  `--fuzzy-class` changes it to descriptor-substring matching.
- Each output line identifies the DEX, the complete caller method signature,
  and the matched target symbols. Batched string output also starts with its
  `query=` group.
- `--debug` writes DEX counts and timings to stderr, leaving results on stdout.

Examples:

```powershell
<asc> findrefs app.apk string Authorization
<asc> findrefs app.apk strings Authorization token api.example.com
<asc> findrefs app.apk type com.example.Main
<asc> findrefs app.apk method onCreate --class com.example.Main
<asc> findrefs app.apk method notify --class openclaw --fuzzy-class
<asc> findrefs app.apk field INSTANCE --class com.example.Store
```

## Decode the manifest

```text
<asc> manifest [--compact] [--format text|json] [-o FILE] APK
```

The default is pretty-printed XML. Use `--compact` only when compact output is
specifically useful.

## Discover classes

```text
<asc> classes [--threads N] [--debug] [--format text|json] \
  [--contains VALUE] [-o FILE] APK
```

This lists definitions from every root `classes*.dex` in DEX/class-table order.
`--contains` is a descriptor substring match; dots in Java package names are
normalized to slashes. Text output contains the DEX name and descriptor. JSON
also includes the Java class name.

## Inspect APK entries

List archive entries without inflating them:

```text
<asc> entries [--contains VALUE] [--format text|json] [-o FILE] APK
```

Read a bounded range, using offsets and lengths in uncompressed bytes:

```text
<asc> entry [--offset N] [--length N] [--encoding utf8|hex|raw] \
  [--format text|json] [-o FILE] APK ENTRY
```

Use `entries` to resolve the exact case-sensitive entry name. `hex` is the
default and includes absolute entry offsets. `utf8` rejects invalid text rather
than replacing bytes. `raw` requires `-o FILE` and cannot be combined with JSON.
Ranges that extend past the entry fail instead of silently truncating.

## Structured output

`getclass`, `findrefs`, `manifest`, `classes`, `decompile-all`, `entries`,
and non-raw `entry` accept `--format json`. The JSON form preserves reference
indexes, bytecode
offsets, DEX summaries, timings, and class/minimal-DEX metadata where relevant.
Diagnostics from `--debug` remain on stderr so stdout stays machine-readable.

## Failures and follow-up

- A missing class means the name or descriptor was not defined in any root
  `classes*.dex`; verify the name rather than widening the operation blindly.
- If JADX cannot launch, report its diagnostic and either accept an explicit
  `--jadx-path` from the user or use `builtin` when engine choice is flexible.
- If structured output is incomplete, retry the same engine with `simple` or
  `fallback` before claiming the class has no relevant behavior.
- A successful decompilation can still contain inaccurate types, variable
  names, or control flow. Base findings on exact constants, calls, fields, and
  signatures where possible.
