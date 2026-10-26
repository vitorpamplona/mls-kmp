
// ---- appended by tools/mlsrs-verifier/run.sh (mls-kmp) ----

/// mls-kmp: replay the passive-client vectors named by MLSKMP_PASSIVE_VECTORS
/// the way `interop_passive_client` replays the mlswg ones.
#[maybe_async::test(not(mls_build_async), async(mls_build_async, crate::futures_test))]
async fn mlskmp_authored_vectors() {
    let Ok(path) = std::env::var("MLSKMP_PASSIVE_VECTORS") else {
        return;
    };
    let test_cases: Vec<TestCase> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(!test_cases.is_empty(), "no vectors in MLSKMP_PASSIVE_VECTORS");

    for (i, test_case) in test_cases.into_iter().enumerate() {
        std::eprintln!("MLSKMP vector {i} START");
        let crypto_provider = TestCryptoProvider::new();
        let cs = crypto_provider
            .cipher_suite_provider(test_case.cipher_suite.into())
            .expect("mls-kmp writes cipher suite 1 only");

        let message = MlsMessage::from_bytes(&test_case.key_package).unwrap();
        let key_package = message.into_key_package().unwrap();
        let id = key_package.leaf_node.signing_identity.clone();
        let key = test_case.signature_priv.clone().into();

        let mut client_builder = ClientBuilder::new()
            .crypto_provider(crypto_provider)
            .identity_provider(BasicIdentityProvider::new());

        for psk in test_case.external_psks {
            client_builder = client_builder.psk(ExternalPskId::new(psk.psk_id), psk.psk.into());
        }

        let client = client_builder
            .signing_identity(id, key, cs.cipher_suite())
            .build();

        let key_pckg_gen = KeyPackageGeneration {
            reference: key_package.to_reference(&cs).await.unwrap(),
            key_package,
            init_secret_key: test_case.init_priv.into(),
            leaf_node_secret_key: test_case.encryption_priv.into(),
        };

        let (id, pkg) = key_pckg_gen.to_storage().unwrap();
        client.config.key_package_repo().insert(id, pkg);

        let welcome = MlsMessage::from_bytes(&test_case.welcome).unwrap();
        let tree = test_case
            .ratchet_tree
            .map(|t| ExportedTree::from_bytes(&t.0).unwrap());

        let (mut group, _info) = client.join_group(tree, &welcome, None).await.unwrap();
        assert_eq!(
            group.epoch_authenticator().unwrap().to_vec(),
            test_case.initial_epoch_authenticator,
            "vector {i}: initial epoch_authenticator"
        );

        for (e, epoch) in test_case.epochs.into_iter().enumerate() {
            for proposal in epoch.proposals.iter() {
                let message = MlsMessage::from_bytes(&proposal.0).unwrap();
                group
                    .process_incoming_message_with_time(message, MlsTime::now())
                    .await
                    .unwrap_or_else(|err| panic!("vector {i} epoch {e}: proposal: {err:?}"));
            }

            let message = MlsMessage::from_bytes(&epoch.commit).unwrap();
            group
                .process_incoming_message_with_time(message, MlsTime::now())
                .await
                .unwrap_or_else(|err| panic!("vector {i} epoch {e}: commit: {err:?}"));

            assert_eq!(
                epoch.epoch_authenticator,
                group.epoch_authenticator().unwrap().to_vec(),
                "vector {i} epoch {e}: epoch_authenticator"
            );
        }
        std::eprintln!("MLSKMP vector {i} PASS");
    }
}
