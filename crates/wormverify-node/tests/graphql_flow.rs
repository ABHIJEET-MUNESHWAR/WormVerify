//! End-to-end GraphQL flow test exercising the assembled schema.

use wormverify_api::{build_schema, ServiceState};
use wormverify_node::config::GuardianArgs;
use wormverify_node::startup::build_state;

fn state() -> ServiceState {
    build_state(
        &GuardianArgs {
            guardian_count: 4, // quorum = 3
            guardian_seed: 5,
            guardian_set_index: 0,
        },
        1000,
    )
}

fn data_field<'a>(value: &'a async_graphql::Value, key: &str) -> &'a async_graphql::Value {
    match value {
        async_graphql::Value::Object(map) => map
            .get(key)
            .unwrap_or_else(|| panic!("missing field {key}")),
        _ => panic!("expected object"),
    }
}

fn as_str(value: &async_graphql::Value) -> String {
    match value {
        async_graphql::Value::String(s) => s.clone(),
        other => panic!("expected string, got {other:?}"),
    }
}

#[tokio::test]
async fn graphql_end_to_end_assembles_and_queries_vaa() {
    let schema = build_schema(state());

    // Observe a message.
    let observe = r#"
        mutation {
            submitObservation(input: {
                guardianSetIndex: 0,
                timestamp: 1700000000,
                nonce: 1,
                emitterChain: 1,
                emitterAddressHex: "1111111111111111111111111111111111111111111111111111111111111111",
                sequence: 42,
                consistencyLevel: 1,
                payloadHex: "deadbeef"
            })
        }
    "#;
    let resp = schema.execute(observe).await;
    assert!(resp.errors.is_empty(), "observe errors: {:?}", resp.errors);
    let message_id = as_str(data_field(&resp.data, "submitObservation"));

    // Reach quorum (3 of 4) via simulated guardians.
    let mut assembled = false;
    for index in 0..3u8 {
        let m = format!(
            r#"mutation {{ signAsGuardian(messageId: "{message_id}", guardianIndex: {index}) {{ assembled have needed }} }}"#
        );
        let resp = schema.execute(m).await;
        assert!(resp.errors.is_empty(), "sign errors: {:?}", resp.errors);
        let sign = data_field(&resp.data, "signAsGuardian");
        if let async_graphql::Value::Boolean(b) = data_field(sign, "assembled") {
            assembled = *b;
        }
    }
    assert!(assembled, "quorum should have assembled a VAA");

    // Query the completed VAA.
    let q = format!(r#"query {{ vaa(id: "{message_id}") {{ numSignatures sequence }} }}"#);
    let resp = schema.execute(q).await;
    assert!(
        resp.errors.is_empty(),
        "vaa query errors: {:?}",
        resp.errors
    );
    let vaa = data_field(&resp.data, "vaa");
    assert_eq!(as_str(data_field(vaa, "sequence")), "42");

    // Stats should report one completed VAA.
    let resp = schema
        .execute("query { stats { pending completed } }")
        .await;
    let stats = data_field(&resp.data, "stats");
    assert_eq!(
        data_field(stats, "completed"),
        &async_graphql::Value::Number(1.into())
    );
}

#[tokio::test]
async fn guardian_set_query_returns_active_set() {
    let schema = build_schema(state());
    let resp = schema
        .execute("query { guardianSet { index quorum addresses } }")
        .await;
    assert!(resp.errors.is_empty(), "errors: {:?}", resp.errors);
    let set = data_field(&resp.data, "guardianSet");
    assert_eq!(
        data_field(set, "quorum"),
        &async_graphql::Value::Number(3.into())
    );
}
