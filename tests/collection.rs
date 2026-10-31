//! Verifies a collection of certificates through Windows CNG and compares the result against
//! the software implementation certval ships with.
//!
//! The collections are named by environment variables rather than carried here; see `README.md`. A
//! test whose collection is not configured reports that and passes.
//!
//! The assertion that matters in every case is **agreement**: for every certificate, the platform and
//! software must reach the same verdict. A collection assembled to exercise a path validator contains
//! signatures that are supposed to fail, and those carry as much weight here as the ones that pass.

#![cfg(windows)]

mod common;

use certval_cng::CngCrypto;
use common::*;
use std::sync::Arc;

/// Reports what the environment has configured, so a run that covers little says so plainly rather
/// than passing quietly.
#[test]
fn harness_configuration_is_reported() {
    for var in [RSA_CERTS, ECDSA_CERTS, PSS_CERTS, MLDSA_CERTS] {
        println!("{var} = {:?}", env(var));
    }
}

/// Runs one family through both interfaces. Returns the number of pairs the platform answered
/// itself, so the caller can tell whether it was exercised or merely bypassed.
fn run_family(family: &str, dir_var: &str) -> usize {
    let Some(dir) = env(dir_var) else {
        println!("{family}: skipped, {dir_var} is not set");
        return 0;
    };
    let crypto = Arc::new(CngCrypto::new());

    let certs = load_certs(&dir).unwrap_or_else(|e| panic!("{family}: {e}"));
    let (pairs, capped) = pairs(&certs);
    if capped {
        println!(
            "{family}: capped at {MAX_PAIRS} pairs; {} certificates in the collection yield more",
            certs.len()
        );
    }
    assert!(
        !pairs.is_empty(),
        "{family}: {} certificates yielded no issuer/subject pairs, so nothing was verified",
        certs.len()
    );

    let envs = Environments::build(&crypto);

    let message = run_message_tests(&envs, &pairs);
    message.report(family, "message");
    assert_eq!(
        message.disagreements, 0,
        "{family}: the platform and software disagreed on {} of {} certificates in the message interface",
        message.disagreements, message.pairs
    );

    let digest = run_digest_tests(&envs, &pairs);
    digest.report(family, "digest");
    assert_eq!(
        digest.disagreements, 0,
        "{family}: the platform and software disagreed on {} of {} certificates in the digest interface",
        digest.disagreements, digest.pairs
    );

    message.module_answered + digest.module_answered
}

#[test]
fn rsa_platform_agrees_with_software() {
    run_family("RSA", RSA_CERTS);
}

#[test]
fn ecdsa_platform_agrees_with_software() {
    run_family("ECDSA", ECDSA_CERTS);
}

#[test]
fn pss_platform_agrees_with_software() {
    run_family("RSASSA-PSS", PSS_CERTS);
}

/// ML-DSA is declined by the provider, so this checks the fall-through path: every verification
/// reaches software and the verdicts still agree.
#[test]
fn ml_dsa_falls_through_to_software() {
    let answered = run_family("ML-DSA", MLDSA_CERTS);
    assert_eq!(answered, 0, "the provider answered an ML-DSA verification");
}

/// With an RSA or ECDSA collection pointed at, the platform must actually verify something.
/// Without this a run in which every verification quietly fell through to software would look
/// identical to a working one.
#[test]
fn platform_is_not_silently_bypassed() {
    let configured: Vec<(&str, &str)> = [("RSA", RSA_CERTS), ("ECDSA", ECDSA_CERTS)]
        .into_iter()
        .filter(|(_, v)| env(v).is_some())
        .collect();
    if configured.is_empty() {
        println!("skipped, no RSA or ECDSA collection configured");
        return;
    }
    let answered: usize = configured
        .into_iter()
        .map(|(family, v)| run_family(family, v))
        .sum();
    assert!(
        answered > 0,
        "an RSA or ECDSA collection was supplied, but the platform answered no verification at all"
    );
}
