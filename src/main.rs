//! Command-line entry point. Parses arguments, reads input files with size
//! limits, calls the library and sets the exit code; all logic lives in the
//! library.
//!
//! Exit codes: 0 no finding at or above `--fail-on` and no hash mismatch;
//! 1 findings at or above `--fail-on`; 2 input, usage or internal error;
//! 3 an expected hash does not match (takes precedence over 1).

#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::{Context as _, anyhow, bail};
use blindsight::addressbook::{AddressBook, MAX_BOOK_BYTES};
use blindsight::decode::UserAbis;
use blindsight::decode::user_abi::MAX_ABI_BYTES;
use blindsight::detect::{Detector, Severity};
use blindsight::input::exec::parse_exec_calldata;
use blindsight::input::fields::{parse_address, parse_bytes, parse_hash, parse_uint};
use blindsight::input::json::parse_json;
use blindsight::input::{
    Field, InputWarning, MAX_CALLDATA_BYTES, MAX_JSON_BYTES, PartialTx, TxFlags, TxInput,
    read_limited,
};
use blindsight::registry::Registry;
use blindsight::report::{self, EXIT_ERROR, Options, Report};
use blindsight::sanitize::sanitize;
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Offline verifier for Safe multisig transactions.
///
/// Computes the domain hash, message hash and safeTxHash your hardware
/// wallet shows, decodes the calldata and flags risky operations. It never
/// uses the network: run it on a different machine from the one that
/// prepared the transaction.
#[derive(Parser)]
#[command(name = "blindsight", version, about, long_about)]
struct Cli {
    /// When to use colours (also honours `NO_COLOR`).
    #[arg(long, value_enum, default_value_t = ColorWhen::Auto, global = true)]
    color: ColorWhen,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorWhen {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Hashes, decoded calls and findings: the full check before signing.
    Verify(VerifyArgs),
    /// Only the domain hash, message hash and safeTxHash.
    Hash(HashArgs),
    /// Only the decoded call tree.
    Decode(DecodeArgs),
    /// List the detectors or explain one.
    Detectors {
        #[command(subcommand)]
        command: DetectorsCommand,
    },
    /// Version and the sources of the embedded data.
    Version,
}

#[derive(Subcommand)]
enum DetectorsCommand {
    /// List every detector with its severities.
    List {
        /// Output format.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Show a detector's documentation.
    Explain {
        /// Detector ID, e.g. BS-DELEGATE-001.
        id: String,
    },
}

/// Where the transaction comes from. Flags can be combined with `--tx` or
/// `--exec-calldata`; a field given twice must have the same value.
#[derive(Args)]
struct TxArgs {
    /// JSON file in the Safe Transaction Service format (`-` for stdin).
    #[arg(long, value_name = "FILE", conflicts_with = "exec_calldata")]
    tx: Option<String>,
    /// Raw execTransaction calldata, hex (`-` for stdin). Needs --nonce,
    /// --safe, --chain-id and --safe-version.
    #[arg(long, value_name = "HEX")]
    exec_calldata: Option<String>,
    /// Chain id (e.g. 1 for Ethereum).
    #[arg(long)]
    chain_id: Option<String>,
    /// Address of the Safe.
    #[arg(long)]
    safe: Option<String>,
    /// Safe contract version (1.0.0, 1.1.1, 1.2.0, 1.3.0, 1.4.1, 1.5.0).
    #[arg(long)]
    safe_version: Option<String>,
    /// Destination address.
    #[arg(long)]
    to: Option<String>,
    /// Native value in wei [default: 0].
    #[arg(long)]
    value: Option<String>,
    /// Calldata, hex [default: empty].
    #[arg(long)]
    data: Option<String>,
    /// 0 or call, 1 or delegatecall [default: 0].
    #[arg(long)]
    operation: Option<String>,
    /// safeTxGas [default: 0].
    #[arg(long)]
    safe_tx_gas: Option<String>,
    /// baseGas [default: 0].
    #[arg(long)]
    base_gas: Option<String>,
    /// gasPrice [default: 0].
    #[arg(long)]
    gas_price: Option<String>,
    /// gasToken [default: zero address].
    #[arg(long)]
    gas_token: Option<String>,
    /// refundReceiver [default: zero address].
    #[arg(long)]
    refund_receiver: Option<String>,
    /// Safe nonce of this transaction.
    #[arg(long)]
    nonce: Option<String>,
    /// Accept a chain id without an official Safe deployment.
    #[arg(long)]
    allow_unknown_chain: bool,
}

/// Hashes shown on your screen, to compare.
#[derive(Args)]
struct ExpectArgs {
    /// Expected safeTxHash.
    #[arg(long, value_name = "HASH")]
    expect_safe_tx_hash: Option<String>,
    /// Expected domain hash (as shown by a Ledger).
    #[arg(long, value_name = "HASH")]
    expect_domain_hash: Option<String>,
    /// Expected message hash (as shown by a Ledger or Trezor).
    #[arg(long, value_name = "HASH")]
    expect_message_hash: Option<String>,
}

/// Extra knowledge for decoding and detectors.
#[derive(Args)]
struct KnowledgeArgs {
    /// JSON object of name -> address, to label addresses and detect look-alikes.
    #[arg(long, value_name = "FILE")]
    address_book: Option<String>,
    /// ABI for one contract: ADDRESS=FILE (repeatable).
    #[arg(long, value_name = "ADDRESS=FILE")]
    abi: Vec<String>,
}

#[derive(Args)]
struct VerifyArgs {
    #[command(flatten)]
    tx: TxArgs,
    #[command(flatten)]
    expect: ExpectArgs,
    #[command(flatten)]
    knowledge: KnowledgeArgs,
    /// The Safe's current nonce, to flag used or far-future nonces.
    #[arg(long, value_name = "NONCE")]
    current_nonce: Option<String>,
    /// Lowest severity that makes the exit code 1.
    #[arg(long, value_name = "SEVERITY", default_value = "high")]
    fail_on: String,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Args)]
struct HashArgs {
    #[command(flatten)]
    tx: TxArgs,
    #[command(flatten)]
    expect: ExpectArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

#[derive(Args)]
struct DecodeArgs {
    #[command(flatten)]
    tx: TxArgs,
    #[command(flatten)]
    knowledge: KnowledgeArgs,
    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let choice = match cli.color {
        ColorWhen::Auto => anstream::ColorChoice::Auto,
        ColorWhen::Always => anstream::ColorChoice::Always,
        ColorWhen::Never => anstream::ColorChoice::Never,
    };
    choice.write_global();
    match run(cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            // Errors may quote input: sanitise like any other output.
            let _ = writeln!(io::stderr(), "error: {}", sanitize(&format!("{err:#}")));
            ExitCode::from(EXIT_ERROR)
        }
    }
}

fn run(command: Command) -> anyhow::Result<u8> {
    match command {
        Command::Verify(args) => {
            let input = read_transaction(&args.tx)?;
            let fail_on: Severity = args
                .fail_on
                .parse()
                .map_err(|e| anyhow!("invalid --fail-on: {e}"))?;
            let (address_book, user_abis, mut book_warnings) = read_knowledge(&args.knowledge)?;
            let current_nonce = args
                .current_nonce
                .as_deref()
                .map(|s| parse_uint(Field::Nonce, s).context("invalid --current-nonce"))
                .transpose()?;
            let options = Options {
                address_book,
                user_abis,
                current_nonce,
                fail_on,
                ..expectations(&args.expect)?
            };
            let mut input = input;
            input.warnings.append(&mut book_warnings);
            let report = report::analyse(report::Command::Verify, input, options)?;
            emit(&report, args.format)
        }
        Command::Hash(args) => {
            let input = read_transaction(&args.tx)?;
            let report =
                report::analyse(report::Command::Hash, input, expectations(&args.expect)?)?;
            emit(&report, args.format)
        }
        Command::Decode(args) => {
            let mut input = read_transaction(&args.tx)?;
            let (address_book, user_abis, mut book_warnings) = read_knowledge(&args.knowledge)?;
            input.warnings.append(&mut book_warnings);
            let options = Options {
                address_book,
                user_abis,
                ..Options::default()
            };
            let report = report::analyse(report::Command::Decode, input, options)?;
            emit(&report, args.format)
        }
        Command::Detectors { command } => {
            match command {
                DetectorsCommand::List { format } => {
                    let text = match format {
                        Format::Text => report::text::detectors_list(),
                        Format::Json => report::json::detectors_list() + "\n",
                    };
                    write_stdout(&text)?;
                }
                DetectorsCommand::Explain { id } => {
                    let detector = Detector::from_id(&id).ok_or_else(|| {
                        anyhow!("unknown detector {id:?}; see `blindsight detectors list`")
                    })?;
                    write_stdout(detector.documentation())?;
                }
            }
            Ok(report::EXIT_OK)
        }
        Command::Version => {
            write_stdout(&version_text()?)?;
            Ok(report::EXIT_OK)
        }
    }
}

fn emit(report: &Report, format: Format) -> anyhow::Result<u8> {
    match format {
        Format::Text => {
            let mut out = anstream::stdout();
            let written = out
                .write_all(report::text::render(report).as_bytes())
                .and_then(|()| out.flush());
            ignore_broken_pipe(written)?;
        }
        Format::Json => write_stdout(&(report::json::render(report) + "\n"))?,
    }
    Ok(report.exit_code())
}

fn write_stdout(text: &str) -> anyhow::Result<()> {
    let mut out = io::stdout().lock();
    let written = out.write_all(text.as_bytes()).and_then(|()| out.flush());
    ignore_broken_pipe(written)
}

/// A reader that stops early (`blindsight ... | head`) is not an error: the
/// exit code still reflects the analysis.
fn ignore_broken_pipe(result: io::Result<()>) -> anyhow::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

/// Reads a file, or standard input for `-`, up to `limit` bytes.
fn read_source(path: &str, limit: usize, what: &'static str) -> anyhow::Result<String> {
    if path == "-" {
        return Ok(read_limited(io::stdin().lock(), limit, what)?);
    }
    let file =
        File::open(path).with_context(|| format!("cannot open {what} {:?}", sanitize(path)))?;
    Ok(read_limited(file, limit, what)?)
}

fn read_transaction(args: &TxArgs) -> anyhow::Result<TxInput> {
    let flags = TxFlags {
        chain_id: args.chain_id.clone(),
        safe: args.safe.clone(),
        safe_version: args.safe_version.clone(),
        to: args.to.clone(),
        value: args.value.clone(),
        data: args.data.clone(),
        operation: args.operation.clone(),
        safe_tx_gas: args.safe_tx_gas.clone(),
        base_gas: args.base_gas.clone(),
        gas_price: args.gas_price.clone(),
        gas_token: args.gas_token.clone(),
        refund_receiver: args.refund_receiver.clone(),
        nonce: args.nonce.clone(),
    };
    let mut partial = flags.parse()?;
    if let Some(path) = &args.tx {
        let text = read_source(path, MAX_JSON_BYTES, "transaction JSON")?;
        partial = partial.merge("command-line flags", parse_json(&text)?, "the JSON file")?;
    }
    if let Some(hex) = &args.exec_calldata {
        let text = if hex == "-" {
            // Hex doubles the size; allow for the prefix and whitespace.
            read_limited(
                io::stdin().lock(),
                2 * MAX_CALLDATA_BYTES + 64,
                "standard input",
            )?
        } else {
            hex.clone()
        };
        let calldata = parse_bytes(Field::ExecCalldata, text.trim())?;
        let from_calldata: PartialTx = parse_exec_calldata(&calldata)?;
        partial = partial.merge(
            "command-line flags",
            from_calldata,
            "the execTransaction calldata",
        )?;
    }
    Ok(partial.finish(args.allow_unknown_chain)?)
}

fn expectations(args: &ExpectArgs) -> anyhow::Result<Options> {
    let parse =
        |field, value: &Option<String>| value.as_deref().map(|s| parse_hash(field, s)).transpose();
    Ok(Options {
        expect_domain_hash: parse(Field::ExpectDomainHash, &args.expect_domain_hash)?,
        expect_message_hash: parse(Field::ExpectMessageHash, &args.expect_message_hash)?,
        expect_safe_tx_hash: parse(Field::ExpectSafeTxHash, &args.expect_safe_tx_hash)?,
        ..Options::default()
    })
}

fn read_knowledge(
    args: &KnowledgeArgs,
) -> anyhow::Result<(Option<AddressBook>, UserAbis, Vec<InputWarning>)> {
    let (book, warnings) = match &args.address_book {
        Some(path) => {
            let text = read_source(path, MAX_BOOK_BYTES, "address book")?;
            let (book, warnings) = AddressBook::parse(&text)?;
            (Some(book), warnings)
        }
        None => (None, Vec::new()),
    };
    let mut abis = UserAbis::default();
    for binding in &args.abi {
        let Some((address, path)) = binding.split_once('=') else {
            bail!("--abi expects ADDRESS=FILE, got {:?}", sanitize(binding));
        };
        let (address, _) = parse_address(Field::To, address).context("invalid address in --abi")?;
        let text = read_source(path, MAX_ABI_BYTES, "ABI file")?;
        abis.add(address, &text)?;
    }
    Ok((book, abis, warnings))
}

fn version_text() -> anyhow::Result<String> {
    let registry = Registry::load()?;
    Ok(format!(
        "blindsight {}\n\
         network access: none (no networking code in this binary)\n\
         embedded data:\n  \
         official Safe contracts: safe-global/safe-deployments {} ({} deployments)\n  \
         chain names: ethereum-lists/chains {} ({} chains)\n  \
         tokens: {} ({} tokens)\n  \
         Permit2: {}\n",
        blindsight::VERSION,
        registry.contracts.source_commit,
        registry.contracts.len(),
        registry.chains.source_commit,
        registry.chains.len(),
        registry.tokens.source,
        registry.tokens.len(),
        registry.permit2.source,
    ))
}
