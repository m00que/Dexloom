//! Reusable high-level operations for CLI and GUI frontends.

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, atomic::{AtomicUsize, Ordering}},
    time::Instant,
};

use anyhow::{Context, Result, anyhow, bail};
use axml_parser::AXMLPrinter;
pub use dex_decompiler::DecompilationMode;
use dex_decompiler::{ClassDef, Decompiler, DecompilerOptions, DexFile, parse_dex};
use rayon::prelude::*;

use crate::{
    apk::{ApkSession, DexEntry},
    descriptor_to_java,
    dex::{Query, ReferenceKind, StringBatchMatcher, class_descriptors_at},
    dex_container::logical_dexes,
    format_class_name,
    minidex::{MinimalDexStats, extract_minimal_dex_at},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStage {
    Loading,
    Indexing,
    Extracting,
    Decompiling,
    Searching,
    Manifest,
}

#[derive(Debug, Clone)]
pub struct ProgressEvent {
    pub stage: OperationStage,
    pub completed: usize,
    pub total: usize,
    pub item: Option<String>,
}

/// Frontends can implement this trait to receive progress and cancel work at
/// stable service boundaries. Callbacks may arrive from worker threads.
pub trait OperationObserver: Sync {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn on_progress(&self, _event: &ProgressEvent) {}
}

struct NoopObserver;

impl OperationObserver for NoopObserver {}

fn check_cancelled(observer: &dyn OperationObserver) -> Result<()> {
    if observer.is_cancelled() {
        bail!("operation cancelled");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecompileTimings {
    pub locate_ms: f64,
    pub extract_ms: f64,
    pub decompile_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug)]
pub struct DecompileResult {
    pub source: String,
    pub descriptor: String,
    pub dex_name: String,
    pub engine: DecompilationEngine,
    pub minimal_stats: MinimalDexStats,
    pub timings: DecompileTimings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DecompilationEngine {
    /// The in-process, pure-Rust `dex-decompiler` backend.
    #[default]
    Builtin,
    /// The external JADX command-line backend.
    Jadx,
}

impl DecompilationEngine {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Builtin => "built-in Rust",
            Self::Jadx => "JADX",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DecompileOptions {
    pub engine: DecompilationEngine,
    pub mode: DecompilationMode,
    /// Optional JADX executable or launcher path. When omitted, ASC-RS searches
    /// PATH for the platform's usual `jadx` launchers.
    pub jadx_executable: Option<PathBuf>,
}

impl Default for DecompileOptions {
    fn default() -> Self {
        Self {
            engine: DecompilationEngine::Builtin,
            mode: DecompilationMode::Simple,
            jadx_executable: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceLocation {
    pub dex_name: String,
    pub caller_index: u32,
    pub caller_method: String,
    pub code_unit_offset: u32,
    pub target_index: u32,
    pub target_symbol: String,
}

#[derive(Debug, Clone)]
pub struct DexSearchSummary {
    pub dex_name: String,
    pub classes: usize,
    pub methods: usize,
    pub matched_targets: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SearchTimings {
    pub load_ms: f64,
    pub scan_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug)]
pub struct ReferenceSearchResult {
    pub references: Vec<ReferenceLocation>,
    pub dexes: Vec<DexSearchSummary>,
    pub timings: SearchTimings,
}

#[derive(Debug, Clone)]
pub struct StringReferenceGroup {
    pub pattern: String,
    pub references: Vec<ReferenceLocation>,
}

#[derive(Debug, Clone)]
pub struct BatchDexSearchSummary {
    pub dex_name: String,
    pub classes: usize,
    pub methods: usize,
    /// Number of matching string-table entries for each input pattern.
    pub matched_targets: Vec<usize>,
}

#[derive(Debug)]
pub struct BatchReferenceSearchResult {
    pub groups: Vec<StringReferenceGroup>,
    pub dexes: Vec<BatchDexSearchSummary>,
    pub timings: SearchTimings,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DecompileAllTimings {
    pub load_ms: f64,
    pub decompile_ms: f64,
    pub total_ms: f64,
}

#[derive(Debug, Clone)]
pub struct DecompileAllFailure {
    pub dex_name: String,
    pub descriptor: String,
    pub error: String,
}

#[derive(Debug)]
pub struct DecompileAllResult {
    pub dexes: usize,
    pub total_classes: usize,
    pub written: usize,
    pub failures: Vec<DecompileAllFailure>,
    pub timings: DecompileAllTimings,
}

/// One standalone DEX parsed by the builtin engine: its logical name, the
/// shared parse, and every `(descriptor, class definition)` pair it defines.
type ParsedStandaloneDex = (String, Arc<DexFile>, Vec<(String, ClassDef)>);

/// One DEX 041 logical sub-file: name, container bytes, header offset within
/// the container, and the descriptors it defines.
type ParsedContainerDex = (String, Arc<[u8]>, usize, Vec<String>);

pub struct AscSession {
    apk: ApkSession,
}

impl AscSession {
    pub fn open(apk_path: impl AsRef<Path>, threads: usize) -> Result<Self> {
        Ok(Self {
            apk: ApkSession::open(apk_path, threads)?,
        })
    }

    pub fn open_with_cache_limit(
        apk_path: impl AsRef<Path>,
        threads: usize,
        max_cached_bytes: usize,
    ) -> Result<Self> {
        Ok(Self {
            apk: ApkSession::open_with_cache_limit(apk_path, threads, max_cached_bytes)?,
        })
    }

    pub fn apk(&self) -> &ApkSession {
        &self.apk
    }

    pub fn decode_manifest(&self, pretty: bool) -> Result<String> {
        decode_manifest_with_observer(self.apk.path(), pretty, &NoopObserver)
    }

    pub fn decode_manifest_with_observer(
        &self,
        pretty: bool,
        observer: &dyn OperationObserver,
    ) -> Result<String> {
        decode_manifest_with_observer(self.apk.path(), pretty, observer)
    }

    pub fn decompile_class(
        &self,
        class_name: &str,
        mode: DecompilationMode,
    ) -> Result<DecompileResult> {
        self.decompile_class_with_options(
            class_name,
            &DecompileOptions {
                mode,
                ..DecompileOptions::default()
            },
        )
    }

    pub fn decompile_class_with_observer(
        &self,
        class_name: &str,
        mode: DecompilationMode,
        observer: &dyn OperationObserver,
    ) -> Result<DecompileResult> {
        self.decompile_class_with_options_and_observer(
            class_name,
            &DecompileOptions {
                mode,
                ..DecompileOptions::default()
            },
            observer,
        )
    }

    pub fn decompile_class_with_options(
        &self,
        class_name: &str,
        options: &DecompileOptions,
    ) -> Result<DecompileResult> {
        self.decompile_class_with_options_and_observer(class_name, options, &NoopObserver)
    }

    pub fn decompile_class_with_options_and_observer(
        &self,
        class_name: &str,
        options: &DecompileOptions,
        observer: &dyn OperationObserver,
    ) -> Result<DecompileResult> {
        let started = Instant::now();
        let descriptor = format_class_name(class_name)?;
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Indexing,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: Some(descriptor.clone()),
        });
        let entry = self
            .apk
            .find_class_with(&descriptor, |index, name| {
                check_cancelled(observer)?;
                observer.on_progress(&ProgressEvent {
                    stage: OperationStage::Indexing,
                    completed: index,
                    total: self.apk.dex_info().len(),
                    item: Some(name.to_owned()),
                });
                Ok(())
            })?
            .with_context(|| format!("class {descriptor} not found in APK"))?;
        let located = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Extracting,
            completed: 0,
            total: 1,
            item: Some(entry.name.clone()),
        });
        let minimal = extract_minimal_dex_at(&entry.data, entry.header_offset, &descriptor)
            .with_context(|| format!("failed to extract {descriptor} from {}", entry.name))?;
        let extracted = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Decompiling,
            completed: 0,
            total: 1,
            item: Some(descriptor.clone()),
        });
        let source = decompile_minimal(&entry, &minimal.bytes, &descriptor, options)?;
        let finished = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Decompiling,
            completed: 1,
            total: 1,
            item: Some(descriptor.clone()),
        });
        Ok(DecompileResult {
            source,
            descriptor,
            dex_name: entry.name,
            engine: options.engine,
            minimal_stats: minimal.stats,
            timings: DecompileTimings {
                locate_ms: (located - started).as_secs_f64() * 1000.0,
                extract_ms: (extracted - located).as_secs_f64() * 1000.0,
                decompile_ms: (finished - extracted).as_secs_f64() * 1000.0,
                total_ms: (finished - started).as_secs_f64() * 1000.0,
            },
        })
    }

    pub fn find_references(&self, query: &Query) -> Result<ReferenceSearchResult> {
        self.find_references_with_observer(query, &NoopObserver)
    }

    pub fn find_references_with_observer(
        &self,
        query: &Query,
        observer: &dyn OperationObserver,
    ) -> Result<ReferenceSearchResult> {
        let started = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: None,
        });
        let entries = self.apk.load_all_parsed_dexes()?;
        let loaded = Instant::now();
        let total = entries.len();
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: total,
            total,
            item: None,
        });
        let completed = AtomicUsize::new(0);
        let batches: Vec<Result<(DexSearchSummary, Vec<ReferenceLocation>)>> =
            self.apk.install(|| {
                entries
                    .par_iter()
                    .map(|entry| {
                        check_cancelled(observer)?;
                        let dex = &entry.dex;
                        let matched = dex.matching_indices_sorted(query);
                        let sites = dex.scan_reference_sites_sorted(query.kind(), &matched)?;
                        let references = sites
                            .into_iter()
                            .map(|site| {
                                Ok(ReferenceLocation {
                                    dex_name: entry.name.clone(),
                                    caller_index: site.caller_index,
                                    caller_method: dex.try_format_method(site.caller_index)?,
                                    code_unit_offset: site.code_unit_offset,
                                    target_index: site.target_index,
                                    target_symbol: dex
                                        .try_format_match(query.kind(), site.target_index)?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        observer.on_progress(&ProgressEvent {
                            stage: OperationStage::Searching,
                            completed: completed.fetch_add(1, Ordering::Relaxed) + 1,
                            total,
                            item: Some(entry.name.clone()),
                        });
                        Ok((
                            DexSearchSummary {
                                dex_name: entry.name.clone(),
                                classes: dex.class_count(),
                                methods: dex.method_count(),
                                matched_targets: matched.len(),
                            },
                            references,
                        ))
                    })
                    .collect()
            });
        let mut summaries = Vec::with_capacity(batches.len());
        let mut references = Vec::new();
        for batch in batches {
            let (summary, mut locations) = batch?;
            summaries.push(summary);
            references.append(&mut locations);
        }
        check_cancelled(observer)?;
        let finished = Instant::now();
        Ok(ReferenceSearchResult {
            references,
            dexes: summaries,
            timings: SearchTimings {
                load_ms: (loaded - started).as_secs_f64() * 1000.0,
                scan_ms: (finished - loaded).as_secs_f64() * 1000.0,
                total_ms: (finished - started).as_secs_f64() * 1000.0,
            },
        })
    }

    /// Find references for several string patterns in one pass over each DEX
    /// string table. Results remain grouped in the same order as `patterns`.
    pub fn find_string_references_batch(
        &self,
        patterns: &[String],
    ) -> Result<BatchReferenceSearchResult> {
        self.find_string_references_batch_with_observer(patterns, &NoopObserver)
    }

    pub fn find_string_references_batch_with_observer(
        &self,
        patterns: &[String],
        observer: &dyn OperationObserver,
    ) -> Result<BatchReferenceSearchResult> {
        if patterns.is_empty() {
            bail!("batch string query needs at least one value");
        }
        let started = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: None,
        });
        let entries = self.apk.load_all_parsed_dexes()?;
        let loaded = Instant::now();
        let matcher = StringBatchMatcher::new(patterns)?;
        let total = entries.len();
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: total,
            total,
            item: None,
        });
        let completed = AtomicUsize::new(0);
        type DexBatch = (BatchDexSearchSummary, Vec<Vec<ReferenceLocation>>);
        let batches: Vec<Result<DexBatch>> = self.apk.install(|| {
            entries
                .par_iter()
                .map(|entry| {
                    check_cancelled(observer)?;
                    let dex = &entry.dex;
                    let matched = dex.matching_string_indices_batch(&matcher);
                    let mut reference_groups = Vec::with_capacity(matched.len());
                    for targets in &matched {
                        let sites =
                            dex.scan_reference_sites_sorted(ReferenceKind::String, targets)?;
                        let references = sites
                            .into_iter()
                            .map(|site| {
                                Ok(ReferenceLocation {
                                    dex_name: entry.name.clone(),
                                    caller_index: site.caller_index,
                                    caller_method: dex.try_format_method(site.caller_index)?,
                                    code_unit_offset: site.code_unit_offset,
                                    target_index: site.target_index,
                                    target_symbol: dex.try_format_match(
                                        ReferenceKind::String,
                                        site.target_index,
                                    )?,
                                })
                            })
                            .collect::<Result<Vec<_>>>()?;
                        reference_groups.push(references);
                    }
                    observer.on_progress(&ProgressEvent {
                        stage: OperationStage::Searching,
                        completed: completed.fetch_add(1, Ordering::Relaxed) + 1,
                        total,
                        item: Some(entry.name.clone()),
                    });
                    Ok((
                        BatchDexSearchSummary {
                            dex_name: entry.name.clone(),
                            classes: dex.class_count(),
                            methods: dex.method_count(),
                            matched_targets: matched.iter().map(Vec::len).collect(),
                        },
                        reference_groups,
                    ))
                })
                .collect()
        });

        let mut groups = patterns
            .iter()
            .map(|pattern| StringReferenceGroup {
                pattern: pattern.clone(),
                references: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut summaries = Vec::with_capacity(batches.len());
        for batch in batches {
            let (summary, reference_groups) = batch?;
            summaries.push(summary);
            for (group, mut references) in groups.iter_mut().zip(reference_groups) {
                group.references.append(&mut references);
            }
        }
        check_cancelled(observer)?;
        let finished = Instant::now();
        Ok(BatchReferenceSearchResult {
            groups,
            dexes: summaries,
            timings: SearchTimings {
                load_ms: (loaded - started).as_secs_f64() * 1000.0,
                scan_ms: (finished - loaded).as_secs_f64() * 1000.0,
                total_ms: (finished - started).as_secs_f64() * 1000.0,
            },
        })
    }

    /// Decompile every class in the APK into a Java source tree under
    /// `output_dir`. Per-class failures are collected instead of aborting.
    pub fn decompile_all(
        &self,
        output_dir: &Path,
        mode: DecompilationMode,
    ) -> Result<DecompileAllResult> {
        self.decompile_all_with_observer(output_dir, mode, &NoopObserver)
    }

    pub fn decompile_all_with_observer(
        &self,
        output_dir: &Path,
        mode: DecompilationMode,
        observer: &dyn OperationObserver,
    ) -> Result<DecompileAllResult> {
        let started = Instant::now();
        check_cancelled(observer)?;
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: 0,
            total: self.apk.dex_info().len(),
            item: None,
        });
        let physical = self.apk.load_all_dexes()?;
        let mut standalone = Vec::new();
        let mut containers = Vec::new();
        for entry in &physical {
            for logical in logical_dexes(&entry.name, &entry.data)? {
                if logical.header_offset == 0 {
                    standalone.push((logical.name, entry.data.clone()));
                } else {
                    containers.push((logical.name, entry.data.clone(), logical.header_offset));
                }
            }
        }

        // Parse each standalone DEX once and share the DexFile across worker
        // threads, each owning its own non-Sync Decompiler. DEX 041 sub-files
        // keep container-absolute offsets, so they go through the per-class
        // minimal-DEX rebuild instead of a shared parse.
        let parsed: Vec<ParsedStandaloneDex> =
            self.apk.install(|| {
                standalone
                    .into_par_iter()
                    .map(|(name, data)| {
                        let parsed = parse_dex(&data)
                            .map_err(|error| anyhow!(error.to_string()))
                            .with_context(|| format!("Androguard dex-parser rejected {name}"))?;
                        let mut classes = Vec::new();
                        for class_def in parsed.class_defs() {
                            let class_def = class_def
                                .map_err(|error| anyhow!(error.to_string()))
                                .context("failed to read class definition")?;
                            let descriptor = parsed
                                .get_type(class_def.class_idx)
                                .map_err(|error| anyhow!(error.to_string()))
                                .context("failed to resolve class descriptor")?;
                            classes.push((descriptor, class_def));
                        }
                        Ok((name, Arc::new(parsed), classes))
                    })
                    .collect::<Result<Vec<_>>>()
            })?;
        let containers: Vec<ParsedContainerDex> = containers
            .into_iter()
            .map(|(name, data, header_offset)| {
                let descriptors = class_descriptors_at(&data, header_offset)
                    .with_context(|| format!("failed to list classes in {name}"))?;
                Ok((name, data, header_offset, descriptors))
            })
            .collect::<Result<Vec<_>>>()?;
        let dex_count = parsed.len() + containers.len();
        let total_classes = parsed
            .iter()
            .map(|(_, _, classes)| classes.len())
            .sum::<usize>()
            + containers
                .iter()
                .map(|(_, _, _, descriptors)| descriptors.len())
                .sum::<usize>();
        let loaded = Instant::now();
        observer.on_progress(&ProgressEvent {
            stage: OperationStage::Loading,
            completed: dex_count,
            total: dex_count,
            item: None,
        });
        check_cancelled(observer)?;

        let workers = self.apk.install(rayon::current_num_threads).max(1);
        let completed = AtomicUsize::new(0);
        enum Job<'a> {
            Standalone {
                dex_name: &'a str,
                parsed: &'a DexFile,
                chunk: &'a [(String, ClassDef)],
            },
            Container {
                dex_name: &'a str,
                data: &'a [u8],
                header_offset: usize,
                descriptors: &'a [String],
            },
        }
        let mut jobs = Vec::new();
        for (name, dex, classes) in &parsed {
            let chunk_size = classes.len().div_ceil(workers);
            for chunk in classes.chunks(chunk_size) {
                jobs.push(Job::Standalone {
                    dex_name: name,
                    parsed: dex,
                    chunk,
                });
            }
        }
        for (name, data, header_offset, descriptors) in &containers {
            jobs.push(Job::Container {
                dex_name: name,
                data,
                header_offset: *header_offset,
                descriptors,
            });
        }

        type JobOutcome = (usize, Vec<DecompileAllFailure>);
        let outcomes: Vec<Result<JobOutcome>> = self.apk.install(|| {
            jobs.par_iter()
                .map(|job| {
                    let mut written = 0;
                    let mut failures = Vec::new();
                    let record = |descriptor: &str,
                                      result: Result<String>,
                                      dex_name: &str,
                                      failures: &mut Vec<DecompileAllFailure>,
                                      written: &mut usize| match result {
                        Ok(source) => match write_java_source(output_dir, descriptor, &source) {
                            Ok(()) => *written += 1,
                            Err(error) => failures.push(DecompileAllFailure {
                                dex_name: dex_name.to_owned(),
                                descriptor: descriptor.to_owned(),
                                error: format!("{error:#}"),
                            }),
                        },
                        Err(error) => failures.push(DecompileAllFailure {
                            dex_name: dex_name.to_owned(),
                            descriptor: descriptor.to_owned(),
                            error: format!("{error:#}"),
                        }),
                    };

                    let job_name = match job {
                        Job::Standalone { dex_name, .. } | Job::Container { dex_name, .. } => {
                            *dex_name
                        }
                    };
                    match job {
                        Job::Standalone {
                            dex_name: _,
                            parsed,
                            chunk,
                        } => {
                            let decompiler = Decompiler::with_options(
                                parsed,
                                DecompilerOptions {
                                    mode,
                                    resource_map: Some(Default::default()),
                                    ..DecompilerOptions::default()
                                },
                            );
                            for (descriptor, class_def) in chunk.iter() {
                                check_cancelled(observer)?;
                                record(
                                    descriptor,
                                    decompile_parsed_class(parsed, &decompiler, class_def, descriptor),
                                    job_name,
                                    &mut failures,
                                    &mut written,
                                );
                                observer.on_progress(&ProgressEvent {
                                    stage: OperationStage::Decompiling,
                                    completed: completed.fetch_add(1, Ordering::Relaxed) + 1,
                                    total: total_classes,
                                    item: Some(job_name.to_owned()),
                                });
                            }
                        }
                        Job::Container {
                            data,
                            header_offset,
                            descriptors,
                            ..
                        } => {
                            for descriptor in descriptors.iter() {
                                check_cancelled(observer)?;
                                let result = extract_minimal_dex_at(
                                    data,
                                    *header_offset,
                                    descriptor,
                                )
                                .and_then(|minimal| {
                                    decompile_minimal_builtin(
                                        job_name,
                                        &minimal.bytes,
                                        descriptor,
                                        mode,
                                    )
                                });
                                record(
                                    descriptor,
                                    result,
                                    job_name,
                                    &mut failures,
                                    &mut written,
                                );
                                observer.on_progress(&ProgressEvent {
                                    stage: OperationStage::Decompiling,
                                    completed: completed.fetch_add(1, Ordering::Relaxed) + 1,
                                    total: total_classes,
                                    item: Some(job_name.to_owned()),
                                });
                            }
                        }
                    }
                    Ok((written, failures))
                })
                .collect()
        });

        let mut written = 0;
        let mut failures = Vec::new();
        for outcome in outcomes {
            let (job_written, mut job_failures) = outcome?;
            written += job_written;
            failures.append(&mut job_failures);
        }
        let finished = Instant::now();
        check_cancelled(observer)?;
        Ok(DecompileAllResult {
            dexes: dex_count,
            total_classes,
            written,
            failures,
            timings: DecompileAllTimings {
                load_ms: (loaded - started).as_secs_f64() * 1000.0,
                decompile_ms: (finished - loaded).as_secs_f64() * 1000.0,
                total_ms: (finished - started).as_secs_f64() * 1000.0,
            },
        })
    }
}

pub fn decode_manifest(apk_path: impl AsRef<Path>, pretty: bool) -> Result<String> {
    decode_manifest_with_observer(apk_path, pretty, &NoopObserver)
}

pub fn decode_manifest_with_observer(
    apk_path: impl AsRef<Path>,
    pretty: bool,
    observer: &dyn OperationObserver,
) -> Result<String> {
    check_cancelled(observer)?;
    observer.on_progress(&ProgressEvent {
        stage: OperationStage::Manifest,
        completed: 0,
        total: 1,
        item: Some("AndroidManifest.xml".to_owned()),
    });
    let data = crate::apk::read_entry(apk_path.as_ref(), "AndroidManifest.xml")?;
    let printer = AXMLPrinter::new(&data);
    anyhow::ensure!(
        printer.is_valid(),
        "AndroidManifest.xml is not valid binary AXML"
    );
    let xml = String::from_utf8(printer.get_xml(pretty))
        .context("decoded AndroidManifest.xml is not UTF-8")?;
    check_cancelled(observer)?;
    observer.on_progress(&ProgressEvent {
        stage: OperationStage::Manifest,
        completed: 1,
        total: 1,
        item: Some("AndroidManifest.xml".to_owned()),
    });
    Ok(xml)
}

fn decompile_minimal(
    entry: &DexEntry,
    bytes: &[u8],
    descriptor: &str,
    options: &DecompileOptions,
) -> Result<String> {
    match options.engine {
        DecompilationEngine::Builtin => {
            decompile_minimal_builtin(&entry.name, bytes, descriptor, options.mode)
        }
        DecompilationEngine::Jadx => decompile_minimal_jadx(
            bytes,
            descriptor,
            options.mode,
            options.jadx_executable.as_deref(),
        ),
    }
}

fn decompile_minimal_builtin(
    dex_name: &str,
    bytes: &[u8],
    descriptor: &str,
    mode: DecompilationMode,
) -> Result<String> {
    let parsed = parse_dex(bytes)
        .map_err(|error| anyhow!(error.to_string()))
        .with_context(|| format!("Androguard dex-parser rejected rebuilt {dex_name}"))?;
    for class_def in parsed.class_defs() {
        let class_def = class_def
            .map_err(|error| anyhow!(error.to_string()))
            .context("failed to read class definition")?;
        let class_type = parsed
            .get_type(class_def.class_idx)
            .map_err(|error| anyhow!(error.to_string()))
            .context("failed to resolve class descriptor")?;
        if class_type != descriptor {
            continue;
        }
        let options = DecompilerOptions {
            mode,
            resource_map: Some(Default::default()),
            ..DecompilerOptions::default()
        };
        let decompiler = Decompiler::with_options(&parsed, options);
        return decompile_parsed_class(&parsed, &decompiler, &class_def, descriptor);
    }
    bail!("class {descriptor} was located but dex-decompiler could not resolve it")
}

/// Decompile one class definition from an already-parsed standalone DEX,
/// restoring compiler-synthesized members and repairing double-encoded UTF-8.
fn decompile_parsed_class(
    parsed: &DexFile,
    decompiler: &Decompiler<'_>,
    class_def: &ClassDef,
    descriptor: &str,
) -> Result<String> {
    let mut source = decompiler
        .decompile_class(class_def)
        .map_err(|error| anyhow!(error.to_string()))
        .with_context(|| format!("failed to decompile {}", descriptor_to_java(descriptor)))?;

    if let Some(class_data) = parsed
        .get_class_data(class_def)
        .map_err(|error| anyhow!(error.to_string()))?
    {
        let class_name = descriptor_to_java(descriptor);
        let simple_name = class_name.rsplit('.').next().unwrap_or(&class_name);
        let mut restored = String::new();
        for method in class_data
            .direct_methods
            .iter()
            .chain(class_data.virtual_methods.iter())
        {
            let info = parsed
                .get_method_info(method.method_idx)
                .map_err(|error| anyhow!(error.to_string()))?;
            let hidden = method.access_flags & 0x40 != 0
                || (info.name.starts_with("access$") && method.access_flags & 0x1000 != 0)
                || info.name.starts_with("$r8$lambda$");
            if hidden {
                restored.push_str(
                    &decompiler
                        .decompile_method(method, Some(simple_name), Some(&class_name))
                        .map_err(|error| anyhow!(error.to_string()))?,
                );
            }
        }
        if !restored.is_empty() {
            let insert_at = source.rfind("\n}").unwrap_or(source.len());
            restored.insert(0, '\n');
            source.insert_str(insert_at, &restored);
        }
    }
    Ok(repair_double_encoded_utf8(source))
}

fn decompile_minimal_jadx(
    bytes: &[u8],
    descriptor: &str,
    mode: DecompilationMode,
    executable: Option<&Path>,
) -> Result<String> {
    let workspace = tempfile::tempdir().context("failed to create temporary JADX workspace")?;
    let dex_path = workspace.path().join("class.dex");
    let source_path = workspace.path().join("class.java");
    fs::write(&dex_path, bytes).context("failed to write temporary minimal DEX for JADX")?;

    let class_name = descriptor_to_java(descriptor);
    let arguments = [
        "--single-class".as_ref(),
        class_name.as_ref(),
        "--single-class-output".as_ref(),
        source_path.as_os_str(),
        "--decompilation-mode".as_ref(),
        decompilation_mode_name(mode).as_ref(),
        "--threads-count".as_ref(),
        "1".as_ref(),
        "--no-res".as_ref(),
        "--quiet".as_ref(),
        dex_path.as_os_str(),
    ];
    let output = run_jadx(executable, &arguments).with_context(|| {
        let requested = executable
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "jadx (from PATH)".to_owned());
        format!("failed to launch JADX via {requested}; install JADX or pass --jadx-path <PATH>")
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let diagnostic = if stderr.trim().is_empty() {
            stdout.trim()
        } else {
            stderr.trim()
        };
        bail!(
            "JADX exited with {} while decompiling {class_name}: {}",
            output.status,
            tail(diagnostic, 8 * 1024)
        );
    }
    let source = fs::read_to_string(&source_path)
        .with_context(|| format!("JADX did not produce source for {class_name}"))?;
    Ok(source.trim_start_matches('\u{feff}').to_owned())
}

fn decompilation_mode_name(mode: DecompilationMode) -> &'static str {
    match mode {
        DecompilationMode::Restructure => "restructure",
        DecompilationMode::Simple => "simple",
        DecompilationMode::Fallback => "fallback",
    }
}

fn run_jadx(executable: Option<&Path>, arguments: &[&std::ffi::OsStr]) -> std::io::Result<Output> {
    if let Some(executable) = executable {
        return Command::new(executable).args(arguments).output();
    }

    #[cfg(windows)]
    let candidates = ["jadx.exe", "jadx.cmd", "jadx.bat", "jadx"];
    #[cfg(not(windows))]
    let candidates = ["jadx"];

    let mut last_error = None;
    for candidate in candidates {
        match Command::new(candidate).args(arguments).output() {
            Ok(output) => return Ok(output),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                last_error = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "JADX executable not found")
    }))
}

fn tail(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut start = text.len() - max_bytes;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    &text[start..]
}

fn repair_double_encoded_utf8(mut text: String) -> String {
    for _ in 0..2 {
        let suspicious_before = text
            .chars()
            .filter(|ch| ('\u{80}'..='\u{ff}').contains(ch))
            .count();
        if suspicious_before == 0 || !text.chars().all(|ch| u32::from(ch) <= 0xff) {
            break;
        }
        let bytes: Vec<u8> = text.chars().map(|ch| ch as u8).collect();
        let Ok(candidate) = String::from_utf8(bytes) else {
            break;
        };
        let suspicious_after = candidate
            .chars()
            .filter(|ch| ('\u{80}'..='\u{ff}').contains(ch))
            .count();
        if suspicious_after >= suspicious_before {
            break;
        }
        text = candidate;
    }
    text
}

/// Map a Java class name onto `<output_dir>/<package path>/<Class>.java`.
/// Malformed names that could escape the output directory or that cannot be
/// used as a file name on Windows are rejected.
fn java_source_path(output_dir: &Path, java_name: &str) -> Result<PathBuf> {
    for segment in java_name.split('.') {
        if segment.is_empty() || segment == ".." {
            bail!("class name {java_name:?} would escape the output directory");
        }
    }
    if java_name
        .bytes()
        .any(|byte| matches!(byte, b'\\' | b':' | b'*' | b'?' | b'"' | b'<' | b'>' | b'|' | 0))
    {
        bail!("class name {java_name:?} contains characters unsafe for file names");
    }
    Ok(output_dir.join(format!("{}.java", java_name.replace('.', std::path::MAIN_SEPARATOR_STR))))
}

fn write_java_source(output_dir: &Path, descriptor: &str, source: &str) -> Result<()> {
    let path = java_source_path(output_dir, &descriptor_to_java(descriptor))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, source).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Cancelled;

    impl OperationObserver for Cancelled {
        fn is_cancelled(&self) -> bool {
            true
        }
    }

    #[test]
    fn cancellation_is_checked_before_io() {
        let error = decode_manifest_with_observer("missing.apk", true, &Cancelled).unwrap_err();
        assert_eq!(error.to_string(), "operation cancelled");
    }

    #[test]
    fn java_source_paths_follow_packages_and_reject_traversal() {
        let path = java_source_path(Path::new("out"), "com.example.Foo$Bar").unwrap();
        assert_eq!(
            path,
            Path::new("out").join(format!(
                "com{sep}example{sep}Foo$Bar.java",
                sep = std::path::MAIN_SEPARATOR
            ))
        );
        assert_eq!(
            java_source_path(Path::new("out"), "Root").unwrap(),
            Path::new("out").join("Root.java")
        );
        for hostile in ["..Evil", "com..Evil", "com.", "com.Evil\\Name", "com.Evil:Name"] {
            assert!(java_source_path(Path::new("out"), hostile).is_err(), "{hostile}");
        }
    }
}
