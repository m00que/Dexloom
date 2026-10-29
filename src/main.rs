use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    io::IsTerminal,
    path::PathBuf,
    sync::Mutex,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use asc_rs::{
    apk::{ApkEntryInfo, list_entries, read_entry_range},
    descriptor_to_java,
    dex::{MemberQuery, Query},
    format_class_name,
    service::{
        AscSession, DecompilationEngine, DecompilationMode, DecompileOptions, OperationObserver,
        OperationStage, ProgressEvent, ReferenceLocation, decode_manifest,
    },
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Value, json};

#[derive(Debug, Parser)]
#[command(
    name = "asc-rs",
    version,
    about = "Fast, on-demand APK/DEX query tool rewritten in Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Locate and decompile one class from an APK.
    Getclass(GetClassArgs),
    /// Find bytecode references across every classes*.dex in an APK.
    Findrefs(FindRefsArgs),
    /// Decode the binary AndroidManifest.xml using Androguard's Rust AXML parser.
    Manifest(ManifestArgs),
    /// List files stored in an APK without extracting them.
    Entries(EntriesArgs),
    /// Read a bounded byte range from one APK entry.
    Entry(EntryArgs),
    /// List or search class definitions across every classes*.dex.
    Classes(ClassesArgs),
    /// Decompile every class into a Java source tree (built-in Rust engine).
    DecompileAll(DecompileAllArgs),
}

#[derive(Debug, Args)]
struct ManifestArgs {
    /// Also write decoded XML to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Do not pretty-print the XML.
    #[arg(long)]
    compact: bool,
    /// Output representation.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Text)]
    format: OutputFormatArg,
    /// Input APK path.
    apk_path: PathBuf,
}

#[derive(Debug, Args)]
struct CommonArgs {
    /// Enable timing and DEX diagnostics.
    #[arg(long)]
    debug: bool,
    /// Worker count used to inflate and scan DEX entries.
    #[arg(long, alias = "thread", default_value_t = 8)]
    threads: usize,
    /// Output representation.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Text)]
    format: OutputFormatArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormatArg {
    Text,
    Json,
}

#[derive(Debug, Args)]
struct EntriesArgs {
    /// Also write the listing to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Keep entries whose names contain this value.
    #[arg(long)]
    contains: Option<String>,
    /// Output representation.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Text)]
    format: OutputFormatArg,
    /// Input APK path.
    apk_path: PathBuf,
}

#[derive(Debug, Args)]
struct EntryArgs {
    /// Also write the selected bytes or rendered output to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Uncompressed byte offset within the entry.
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Number of uncompressed bytes to read.
    #[arg(long)]
    length: Option<u64>,
    /// How to render the selected bytes.
    #[arg(long, value_enum, default_value_t = EntryEncodingArg::Hex)]
    encoding: EntryEncodingArg,
    /// Output representation; JSON is unavailable with raw encoding.
    #[arg(long, value_enum, default_value_t = OutputFormatArg::Text)]
    format: OutputFormatArg,
    /// Input APK path.
    apk_path: PathBuf,
    /// Exact ZIP entry name, such as assets/logo.png.
    entry_name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EntryEncodingArg {
    Utf8,
    Hex,
    Raw,
}

impl EntryEncodingArg {
    fn label(self) -> &'static str {
        match self {
            Self::Utf8 => "utf8",
            Self::Hex => "hex",
            Self::Raw => "raw",
        }
    }
}

#[derive(Debug, Args)]
struct ClassesArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Also write the class listing to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Keep descriptors containing this value; Java dots become slashes.
    #[arg(long)]
    contains: Option<String>,
    /// Input APK path.
    apk_path: PathBuf,
}

#[derive(Debug, Args)]
struct DecompileAllArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Directory that receives the <package path>/<Class>.java tree.
    #[arg(short, long, default_value = ".")]
    output: PathBuf,
    /// Backend strategy (default: simple).
    #[arg(short = 'm', long, value_enum)]
    decompilation_mode: Option<ModeArg>,
    /// Input APK path.
    apk_path: PathBuf,
}

#[derive(Debug, Args)]
struct GetClassArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Also write decompiled source to this path.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Decompiler backend.
    #[arg(long, value_enum, default_value_t = EngineArg::Builtin)]
    engine: EngineArg,
    /// Explicit JADX executable or launcher path (only with --engine jadx).
    #[arg(long, value_name = "PATH")]
    jadx_path: Option<PathBuf>,
    /// Backend strategy (default: simple for built-in, restructure for JADX).
    #[arg(short = 'm', long, value_enum)]
    decompilation_mode: Option<ModeArg>,
    /// Input APK path.
    apk_path: PathBuf,
    /// Dalvik descriptor or Java class name.
    dalvik_class: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum EngineArg {
    Builtin,
    Jadx,
}

impl From<EngineArg> for DecompilationEngine {
    fn from(value: EngineArg) -> Self {
        match value {
            EngineArg::Builtin => Self::Builtin,
            EngineArg::Jadx => Self::Jadx,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ModeArg {
    Restructure,
    Simple,
    Fallback,
}

impl From<ModeArg> for DecompilationMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Restructure => Self::Restructure,
            ModeArg::Simple => Self::Simple,
            ModeArg::Fallback => Self::Fallback,
        }
    }
}

impl ModeArg {
    fn label(self) -> &'static str {
        match self {
            Self::Restructure => "restructure",
            Self::Simple => "simple",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Debug, Args)]
struct FindRefsArgs {
    #[command(flatten)]
    common: CommonArgs,
    /// Also write the search results to this path.
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
    /// Input APK path.
    apk_path: PathBuf,
    #[command(subcommand)]
    query: FindQuery,
}

#[derive(Debug, Subcommand)]
enum FindQuery {
    /// Find references to strings containing this value.
    String { value: String },
    /// Find references to several string values in one shared scan.
    Strings {
        #[arg(required = true, num_args = 1..)]
        values: Vec<String>,
    },
    /// Find references to type descriptors containing this value.
    Type { value: String },
    /// Find references to matching methods.
    Method(MemberArgs),
    /// Find references to matching fields.
    Field(MemberArgs),
}

#[derive(Debug, Args)]
struct MemberArgs {
    /// Fuzzy member name; omit it to match all members in --class.
    name: Option<String>,
    /// Exact Java/Dalvik class name, unless --fuzzy-class is set.
    #[arg(long = "class")]
    class_name: Option<String>,
    /// Treat --class as a descriptor substring.
    #[arg(long)]
    fuzzy_class: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Getclass(args) => getclass(args),
        Commands::Findrefs(args) => findrefs(args),
        Commands::Manifest(args) => manifest(args),
        Commands::Entries(args) => entries(args),
        Commands::Entry(args) => entry(args),
        Commands::Classes(args) => classes(args),
        Commands::DecompileAll(args) => decompile_all(args),
    }
}

fn manifest(args: ManifestArgs) -> Result<()> {
    let xml = decode_manifest(&args.apk_path, !args.compact)?;
    match args.format {
        OutputFormatArg::Text => write_and_print(&xml, args.output.as_ref()),
        OutputFormatArg::Json => write_json(
            &json!({
                "apk": args.apk_path.display().to_string(),
                "pretty": !args.compact,
                "xml": xml,
            }),
            args.output.as_ref(),
        ),
    }
}

fn entries(args: EntriesArgs) -> Result<()> {
    let entries = list_entries(&args.apk_path)?
        .into_iter()
        .filter(|entry| {
            args.contains
                .as_ref()
                .is_none_or(|pattern| entry.name.contains(pattern))
        })
        .collect::<Vec<_>>();
    match args.format {
        OutputFormatArg::Text => {
            let text = entries
                .iter()
                .map(|entry| {
                    format!(
                        "{} | compressed={} uncompressed={}{}",
                        entry.name,
                        entry.compressed_size,
                        entry.uncompressed_size,
                        if entry.is_directory { " directory" } else { "" }
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            write_and_print(&text, args.output.as_ref())
        }
        OutputFormatArg::Json => write_json(
            &Value::Array(entries.iter().map(apk_entry_json).collect()),
            args.output.as_ref(),
        ),
    }
}

fn entry(args: EntryArgs) -> Result<()> {
    if args.encoding == EntryEncodingArg::Raw {
        if args.format == OutputFormatArg::Json {
            bail!("--encoding raw cannot be combined with --format json");
        }
        let output = args.output.as_ref().context(
            "--encoding raw requires --output to avoid writing binary data to the terminal",
        )?;
        let data = read_entry_range(&args.apk_path, &args.entry_name, args.offset, args.length)?;
        fs::write(output, &data)
            .with_context(|| format!("failed to write {}", output.display()))?;
        eprintln!(
            "Wrote {} bytes from {} at offset {} to {}",
            data.len(),
            args.entry_name,
            args.offset,
            output.display()
        );
        return Ok(());
    }

    let data = read_entry_range(&args.apk_path, &args.entry_name, args.offset, args.length)?;
    let rendered = render_entry_bytes(&data, args.offset, args.encoding)?;
    match args.format {
        OutputFormatArg::Text => write_and_print(&rendered, args.output.as_ref()),
        OutputFormatArg::Json => write_json(
            &json!({
                "apk": args.apk_path.display().to_string(),
                "entry": args.entry_name,
                "offset": args.offset,
                "length": data.len(),
                "encoding": args.encoding.label(),
                "data": rendered,
            }),
            args.output.as_ref(),
        ),
    }
}

fn classes(args: ClassesArgs) -> Result<()> {
    let started = Instant::now();
    let session = AscSession::open(&args.apk_path, args.common.threads)?;
    let normalized = args.contains.map(|pattern| pattern.replace('.', "/"));
    let classes = session
        .apk()
        .list_classes()?
        .into_iter()
        .filter(|class| {
            normalized
                .as_ref()
                .is_none_or(|pattern| class.descriptor.contains(pattern))
        })
        .collect::<Vec<_>>();
    match args.common.format {
        OutputFormatArg::Text => {
            let text = classes
                .iter()
                .map(|class| format!("{} | {}", class.dex_name, class.descriptor))
                .collect::<Vec<_>>()
                .join("\n");
            write_and_print(&text, args.output.as_ref())?;
        }
        OutputFormatArg::Json => {
            let values = classes
                .iter()
                .map(|class| {
                    json!({
                        "dex_name": class.dex_name,
                        "descriptor": class.descriptor,
                        "java_name": descriptor_to_java(&class.descriptor),
                    })
                })
                .collect();
            write_json(&Value::Array(values), args.output.as_ref())?;
        }
    }
    if args.common.debug {
        eprintln!("[DEBUG] Classes: {}", classes.len());
        eprintln!(
            "[DEBUG] Total: {:.3} ms",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

fn decompile_all(args: DecompileAllArgs) -> Result<()> {
    let mode = args.decompilation_mode.unwrap_or(ModeArg::Simple);
    let session = AscSession::open(&args.apk_path, args.common.threads)?;
    let progress = DecompileAllProgress::new();
    let result = session.decompile_all_with_observer(&args.output, mode.into(), &progress)?;
    match args.common.format {
        OutputFormatArg::Text => {
            println!(
                "Decompiled {}/{} classes from {} DEX file(s) into {}",
                result.written,
                result.total_classes,
                result.dexes,
                args.output.display()
            );
            const SHOWN_FAILURES: usize = 20;
            for failure in result.failures.iter().take(SHOWN_FAILURES) {
                println!("[FAIL] {} ({}): {}", failure.descriptor, failure.dex_name, failure.error);
            }
            if result.failures.len() > SHOWN_FAILURES {
                println!(
                    "... and {} more failures",
                    result.failures.len() - SHOWN_FAILURES
                );
            }
        }
        OutputFormatArg::Json => {
            write_json(
                &json!({
                    "apk": args.apk_path.display().to_string(),
                    "output": args.output.display().to_string(),
                    "mode": mode.label(),
                    "dexes": result.dexes,
                    "total_classes": result.total_classes,
                    "written": result.written,
                    "failures": result
                        .failures
                        .iter()
                        .map(|failure| {
                            json!({
                                "dex": failure.dex_name,
                                "class": failure.descriptor,
                                "error": failure.error,
                            })
                        })
                        .collect::<Vec<_>>(),
                    "timings_ms": {
                        "load": result.timings.load_ms,
                        "decompile": result.timings.decompile_ms,
                        "total": result.timings.total_ms,
                    },
                }),
                None,
            )?;
        }
    }
    if args.common.debug {
        eprintln!(
            "[DEBUG] Load: {:.3} ms, decompile: {:.3} ms, total: {:.3} ms",
            result.timings.load_ms, result.timings.decompile_ms, result.timings.total_ms
        );
    }
    Ok(())
}

/// Stderr progress reporter for `decompile-all`. On a terminal it refreshes
/// one line per second; redirected stderr gets at most one line every 30
/// seconds so logs stay readable. Stdout is never touched.
struct DecompileAllProgress {
    is_tty: bool,
    timing: Mutex<ProgressTiming>,
}

#[derive(Default)]
struct ProgressTiming {
    /// Set when the first Decompiling event arrives, so rate and ETA exclude
    /// the DEX loading phase.
    phase_start: Option<Instant>,
    last_emit: Option<Instant>,
}

impl DecompileAllProgress {
    fn new() -> Self {
        Self {
            is_tty: std::io::stderr().is_terminal(),
            timing: Mutex::new(ProgressTiming::default()),
        }
    }
}

fn format_eta(seconds: u64) -> String {
    let (hours, minutes, secs) = (seconds / 3600, (seconds % 3600) / 60, seconds % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes:02}:{secs:02}")
    }
}

impl OperationObserver for DecompileAllProgress {
    fn on_progress(&self, event: &ProgressEvent) {
        match event.stage {
            OperationStage::Loading if event.completed == 0 => {
                eprintln!("Loading DEX files...");
            }
            OperationStage::Decompiling if event.total > 0 => {
                let interval = if self.is_tty { 1 } else { 30 };
                let finished = event.completed == event.total;
                let mut timing = self.timing.lock().expect("progress lock was poisoned");
                let phase_start = *timing.phase_start.get_or_insert_with(Instant::now);
                if !finished
                    && timing
                        .last_emit
                        .is_some_and(|last| last.elapsed().as_secs() < interval)
                {
                    return;
                }
                timing.last_emit = Some(Instant::now());
                let phase_elapsed = phase_start.elapsed().as_secs_f64();
                let (rate_text, eta_text) = if phase_elapsed < 1.0 {
                    ("--".to_owned(), "--:--".to_owned())
                } else {
                    let rate = event.completed as f64 / phase_elapsed;
                    let remaining = if finished || rate <= 0.0 {
                        0
                    } else {
                        ((event.total - event.completed) as f64 / rate).ceil() as u64
                    };
                    (format!("{rate:.0}/s"), format_eta(remaining))
                };
                let line = format!(
                    "[{:5.1}%] {}/{} classes ({}) {} ETA {}",
                    event.completed as f64 / event.total as f64 * 100.0,
                    event.completed,
                    event.total,
                    event.item.as_deref().unwrap_or("-"),
                    rate_text,
                    eta_text,
                );
                if self.is_tty {
                    eprint!("\r{line}");
                    if finished {
                        eprintln!();
                    }
                } else {
                    eprintln!("{line}");
                }
            }
            _ => {}
        }
    }
}

fn getclass(args: GetClassArgs) -> Result<()> {
    if args.engine == EngineArg::Builtin && args.jadx_path.is_some() {
        bail!("--jadx-path requires --engine jadx");
    }
    let session = AscSession::open(&args.apk_path, args.common.threads)?;
    let mode = args.decompilation_mode.unwrap_or(match args.engine {
        EngineArg::Builtin => ModeArg::Simple,
        EngineArg::Jadx => ModeArg::Restructure,
    });
    let options = DecompileOptions {
        engine: args.engine.into(),
        mode: mode.into(),
        jadx_executable: args.jadx_path,
    };
    let result = session.decompile_class_with_options(&args.dalvik_class, &options)?;
    match args.common.format {
        OutputFormatArg::Text => write_and_print(&result.source, args.output.as_ref())?,
        OutputFormatArg::Json => {
            let stats = result.minimal_stats;
            write_json(
                &json!({
                    "apk": args.apk_path.display().to_string(),
                    "descriptor": result.descriptor,
                    "dex_name": result.dex_name,
                    "engine": match result.engine {
                        DecompilationEngine::Builtin => "builtin",
                        DecompilationEngine::Jadx => "jadx",
                    },
                    "mode": mode.label(),
                    "source": result.source,
                    "minimal_dex": {
                        "input_bytes": stats.input_bytes,
                        "output_bytes": stats.output_bytes,
                        "strings": stats.strings,
                        "types": stats.types,
                        "protos": stats.protos,
                        "fields": stats.fields,
                        "methods": stats.methods,
                    },
                    "timings_ms": decompile_timings_json(result.timings),
                }),
                args.output.as_ref(),
            )?;
        }
    }

    if args.common.debug {
        let stats = result.minimal_stats;
        eprintln!("[DEBUG] Hit DEX: {}", result.dex_name);
        eprintln!(
            "[DEBUG] Minimal DEX: {} -> {} bytes ({:.1}x smaller), strings={} types={} protos={} fields={} methods={}",
            stats.input_bytes,
            stats.output_bytes,
            stats.input_bytes as f64 / stats.output_bytes as f64,
            stats.strings,
            stats.types,
            stats.protos,
            stats.fields,
            stats.methods
        );
        eprintln!(
            "[DEBUG] APK locate/index: {:.3} ms",
            result.timings.locate_ms
        );
        eprintln!(
            "[DEBUG] Extract/rebuild: {:.3} ms",
            result.timings.extract_ms
        );
        eprintln!("[DEBUG] Engine: {}", result.engine.display_name());
        eprintln!("[DEBUG] Decompile: {:.3} ms", result.timings.decompile_ms);
        eprintln!("[DEBUG] Total: {:.3} ms", result.timings.total_ms);
    }
    let cleanup_started = Instant::now();
    drop(session);
    if args.common.debug {
        eprintln!(
            "[DEBUG] Session cleanup: {:.3} ms",
            cleanup_started.elapsed().as_secs_f64() * 1000.0
        );
    }
    Ok(())
}

fn member_query(args: MemberArgs) -> Result<MemberQuery> {
    if args.name.as_deref().is_none_or(str::is_empty)
        && args.class_name.as_deref().is_none_or(str::is_empty)
    {
        bail!("member query needs at least a name or --class");
    }
    let class = match args.class_name {
        Some(value) if args.fuzzy_class => Some(value.replace('.', "/")),
        Some(value) => Some(format_class_name(&value)?),
        None => None,
    };
    Ok(MemberQuery {
        class,
        fuzzy_class: args.fuzzy_class,
        name: args.name.filter(|value| !value.is_empty()),
    })
}

fn findrefs(args: FindRefsArgs) -> Result<()> {
    let FindRefsArgs {
        common,
        output,
        apk_path,
        query,
    } = args;
    let session = AscSession::open(&apk_path, common.threads)?;
    if let FindQuery::Strings { values } = query {
        let result = session.find_string_references_batch(&values)?;
        let result_count = result
            .groups
            .iter()
            .map(|group| group.references.len())
            .sum::<usize>();
        let rendered_count = match common.format {
            OutputFormatArg::Text => {
                let lines = result
                    .groups
                    .iter()
                    .flat_map(|group| {
                        reference_lines(&group.references)
                            .into_iter()
                            .map(|line| format!("query={:?} | {line}", group.pattern))
                    })
                    .collect::<Vec<_>>();
                let count = lines.len();
                write_reference_lines(&lines, output.as_ref())?;
                count
            }
            OutputFormatArg::Json => {
                write_json(
                    &json!({
                        "kind": "strings",
                        "groups": result.groups.iter().map(|group| json!({
                            "pattern": group.pattern,
                            "references": group.references.iter().map(reference_json).collect::<Vec<_>>(),
                        })).collect::<Vec<_>>(),
                        "dexes": result.dexes.iter().map(|dex| json!({
                            "dex_name": dex.dex_name,
                            "classes": dex.classes,
                            "methods": dex.methods,
                            "matched_targets": dex.matched_targets,
                        })).collect::<Vec<_>>(),
                        "timings_ms": search_timings_json(result.timings),
                    }),
                    output.as_ref(),
                )?;
                result_count
            }
        };

        if common.debug {
            for dex in &result.dexes {
                eprintln!(
                    "[DEBUG] {} classes={} methods={} matched={:?}",
                    dex.dex_name, dex.classes, dex.methods, dex.matched_targets
                );
            }
            print_search_timings(result.timings, rendered_count);
        }
        return Ok(());
    }

    let query = match query {
        FindQuery::String { value } => Query::String(value),
        FindQuery::Type { value } => Query::Type(value.replace('.', "/")),
        FindQuery::Method(member) => Query::Method(member_query(member)?),
        FindQuery::Field(member) => Query::Field(member_query(member)?),
        FindQuery::Strings { .. } => unreachable!(),
    };
    let result = session.find_references(&query)?;
    let rendered_count = match common.format {
        OutputFormatArg::Text => {
            let lines = reference_lines(&result.references);
            let count = lines.len();
            write_reference_lines(&lines, output.as_ref())?;
            count
        }
        OutputFormatArg::Json => {
            write_json(
                &json!({
                    "query": query_json(&query),
                    "references": result.references.iter().map(reference_json).collect::<Vec<_>>(),
                    "dexes": result.dexes.iter().map(|dex| json!({
                        "dex_name": dex.dex_name,
                        "classes": dex.classes,
                        "methods": dex.methods,
                        "matched_targets": dex.matched_targets,
                    })).collect::<Vec<_>>(),
                    "timings_ms": search_timings_json(result.timings),
                }),
                output.as_ref(),
            )?;
            result.references.len()
        }
    };

    if common.debug {
        for dex in &result.dexes {
            eprintln!(
                "[DEBUG] {} classes={} methods={} matched={}",
                dex.dex_name, dex.classes, dex.methods, dex.matched_targets
            );
        }
        print_search_timings(result.timings, rendered_count);
    }
    Ok(())
}

fn reference_lines(references: &[ReferenceLocation]) -> Vec<String> {
    let mut grouped = BTreeMap::<(String, u32, String), BTreeSet<String>>::new();
    for reference in references {
        grouped
            .entry((
                reference.dex_name.clone(),
                reference.caller_index,
                reference.caller_method.clone(),
            ))
            .or_default()
            .insert(reference.target_symbol.clone());
    }
    grouped
        .into_iter()
        .map(|((dex_name, _, caller), matches)| {
            format!(
                "{dex_name} | {caller} | matched=({})",
                matches.into_iter().collect::<Vec<_>>().join("; ")
            )
        })
        .collect()
}

fn write_reference_lines(lines: &[String], output: Option<&PathBuf>) -> Result<()> {
    let text = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    write_and_print(&text, output)
}

fn print_search_timings(timings: asc_rs::service::SearchTimings, results: usize) {
    eprintln!("[DEBUG] DEX load/parse: {:.3} ms", timings.load_ms);
    eprintln!("[DEBUG] DEX scan: {:.3} ms", timings.scan_ms);
    eprintln!("[DEBUG] Total: {:.3} ms", timings.total_ms);
    eprintln!("[DEBUG] Results: {results}");
}

fn apk_entry_json(entry: &ApkEntryInfo) -> Value {
    json!({
        "name": entry.name,
        "compressed_size": entry.compressed_size,
        "uncompressed_size": entry.uncompressed_size,
        "is_directory": entry.is_directory,
    })
}

fn render_entry_bytes(data: &[u8], base_offset: u64, encoding: EntryEncodingArg) -> Result<String> {
    match encoding {
        EntryEncodingArg::Utf8 => Ok(std::str::from_utf8(data)
            .context("selected entry bytes are not valid UTF-8; use --encoding hex or raw")?
            .to_owned()),
        EntryEncodingArg::Hex => {
            let mut rendered = String::new();
            for (row_index, row) in data.chunks(16).enumerate() {
                if row_index > 0 {
                    rendered.push('\n');
                }
                let address = base_offset.saturating_add((row_index * 16) as u64);
                write!(rendered, "{address:08x}  ")?;
                for column in 0..16 {
                    if let Some(byte) = row.get(column) {
                        write!(rendered, "{byte:02x} ")?;
                    } else {
                        rendered.push_str("   ");
                    }
                    if column == 7 {
                        rendered.push(' ');
                    }
                }
                rendered.push_str(" | ");
                for &byte in row {
                    rendered.push(if byte.is_ascii_graphic() || byte == b' ' {
                        char::from(byte)
                    } else {
                        '.'
                    });
                }
            }
            Ok(rendered)
        }
        EntryEncodingArg::Raw => unreachable!("raw bytes are written before rendering"),
    }
}

fn reference_json(reference: &ReferenceLocation) -> Value {
    json!({
        "dex_name": reference.dex_name,
        "caller_index": reference.caller_index,
        "caller_method": reference.caller_method,
        "code_unit_offset": reference.code_unit_offset,
        "target_index": reference.target_index,
        "target_symbol": reference.target_symbol,
    })
}

fn query_json(query: &Query) -> Value {
    match query {
        Query::String(value) => json!({ "kind": "string", "value": value }),
        Query::Type(value) => json!({ "kind": "type", "value": value }),
        Query::Method(member) => member_query_json("method", member),
        Query::Field(member) => member_query_json("field", member),
    }
}

fn member_query_json(kind: &str, query: &MemberQuery) -> Value {
    json!({
        "kind": kind,
        "class": query.class,
        "fuzzy_class": query.fuzzy_class,
        "name": query.name,
    })
}

fn decompile_timings_json(timings: asc_rs::service::DecompileTimings) -> Value {
    json!({
        "locate": timings.locate_ms,
        "extract": timings.extract_ms,
        "decompile": timings.decompile_ms,
        "total": timings.total_ms,
    })
}

fn search_timings_json(timings: asc_rs::service::SearchTimings) -> Value {
    json!({
        "load": timings.load_ms,
        "scan": timings.scan_ms,
        "total": timings.total_ms,
    })
}

fn write_json(value: &Value, output: Option<&PathBuf>) -> Result<()> {
    let text = serde_json::to_string_pretty(value).context("failed to serialize JSON output")?;
    write_and_print(&text, output)
}

fn write_and_print(text: &str, output: Option<&PathBuf>) -> Result<()> {
    if let Some(output) = output {
        fs::write(output, text.as_bytes())
            .with_context(|| format!("failed to write {}", output.display()))?;
    }
    print!("{text}");
    if !text.is_empty() && !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eta_formatting_pads_minutes_and_seconds() {
        assert_eq!(format_eta(0), "00:00");
        assert_eq!(format_eta(59), "00:59");
        assert_eq!(format_eta(75), "01:15");
        assert_eq!(format_eta(3725), "1:02:05");
    }

    #[test]
    fn hex_renderer_includes_absolute_offsets_and_ascii() {
        let rendered = render_entry_bytes(b"ABCDEFGHijklmnop!\0", 0x20, EntryEncodingArg::Hex)
            .expect("hex render should succeed");

        let lines = rendered.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("00000020  41 42 43 44 45 46 47 48"));
        assert!(lines[0].ends_with("| ABCDEFGHijklmnop"));
        assert!(lines[1].starts_with("00000030  21 00"));
        assert!(lines[1].ends_with("| !."));
    }

    #[test]
    fn utf8_renderer_rejects_invalid_bytes() {
        let error = render_entry_bytes(&[0xff], 0, EntryEncodingArg::Utf8)
            .expect_err("invalid UTF-8 should fail");
        assert!(error.to_string().contains("not valid UTF-8"));
    }
}
