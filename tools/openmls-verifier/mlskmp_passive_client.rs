
// ---- appended by tools/openmls-verifier/run.sh (mls-kmp) ----

/// mls-kmp: replay the passive-client vectors named by MLSKMP_PASSIVE_VECTORS
/// through OpenMLS's own passive-client KAT runner.
#[test]
fn test_mlskmp_authored_vectors() {
    let Ok(path) = std::env::var("MLSKMP_PASSIVE_VECTORS") else {
        return;
    };
    let data = std::fs::read_to_string(path).unwrap();
    let scenario: Vec<PassiveClientWelcomeTestVector> = serde_json::from_str(&data).unwrap();
    assert!(!scenario.is_empty(), "no vectors in MLSKMP_PASSIVE_VECTORS");
    for (i, test_vector) in scenario.into_iter().enumerate() {
        eprintln!("MLSKMP vector {i} START");
        run_test_vector(test_vector);
        eprintln!("MLSKMP vector {i} PASS");
    }
}
