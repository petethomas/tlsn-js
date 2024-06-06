//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use serde_json::Value;
use std::{collections::HashMap, str};
use wasm_bindgen_test::*;
use web_sys::RequestInit;

extern crate tlsn_extension_rs;
use tlsn_extension_rs::*;

macro_rules! log {
    ( $( $t:tt )* ) => {
        web_sys::console::log_1(&format!( $( $t )* ).into());
    }
}

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
async fn test_fetch() {
    let url = "https://swapi.info/api/";
    let mut opts = RequestInit::new();
    opts.method("GET");

    let rust_string: String = tlsn_extension_rs::fetch_as_json_string(&url, &opts)
        .await
        .unwrap();

    assert!(rust_string.contains("starships"));
}

#[wasm_bindgen_test]
async fn verify() {
    let pem = str::from_utf8(include_bytes!("../../../test/assets/notary.pem")).unwrap();
    let proof = str::from_utf8(include_bytes!(
        "../../../test/assets/simple_proof_redacted.json"
    ))
    .unwrap();
    let m: HashMap<String, Value> = serde_json::from_str(
        &str::from_utf8(include_bytes!(
            "../../../test/assets/simple_proof_expected.json"
        ))
        .unwrap(),
    )
    .unwrap();

    let result = tlsn_extension_rs::verify(proof, pem).await.expect("result");

    log!("result: {}", &result);

    let r: VerifyResult = serde_json::from_str::<VerifyResult>(&result).unwrap();

    assert_eq!(r.server_name, m["serverName"]);
    assert!(r.recv.contains("<title>XXXXXXXXXXXXXX</title>"));
    assert_eq!(r.time, m["time"].as_u64().unwrap());
    assert_eq!(r.sent, m["sent"].as_str().unwrap());
    assert_eq!(r.recv, m["recv"].as_str().unwrap());
}

use futures::{channel::oneshot, future::TryFutureExt};
use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory, Vm};
use tlsn_block_cipher::{Aes128, BlockCipher, BlockCipherConfig, MpcBlockCipher};
use wasm_bindgen_futures::spawn_local;

// This test was copied from tlsn/components/cipher/block-cipher/src/lib.rs
#[wasm_bindgen_test]
async fn test_block_cipher_share() {
    let leader_config = BlockCipherConfig::builder().id("test").build().unwrap();
    let follower_config = BlockCipherConfig::builder().id("test").build().unwrap();

    let key = [0u8; 16];

    let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test").await;
    let leader_thread = leader_vm.new_thread("test").await.unwrap();
    let follower_thread = follower_vm.new_thread("test").await.unwrap();

    // Key is public just for this test, typically it is private.
    let leader_key = leader_thread.new_public_input::<[u8; 16]>("key").unwrap();
    let follower_key = follower_thread.new_public_input::<[u8; 16]>("key").unwrap();

    leader_thread.assign(&leader_key, key).unwrap();
    follower_thread.assign(&follower_key, key).unwrap();

    let mut leader = MpcBlockCipher::<Aes128, _>::new(leader_config, leader_thread);
    leader.set_key(leader_key);

    let mut follower = MpcBlockCipher::<Aes128, _>::new(follower_config, follower_thread);
    follower.set_key(follower_key);

    let plaintext = [0u8; 16];

    // // Commenting out the original code which does not compile to wasm
    //
    // let (leader_share, follower_share) = tokio::try_join!(
    //     leader.encrypt_share(plaintext.to_vec()),
    //     follower.encrypt_share(plaintext.to_vec())
    // )
    // .unwrap();

    // //Approach 1: using futures::try_join! causes a deadlock
    // log!("will join");

    // let (leader_share, follower_share) = futures::try_join!(
    //     leader.encrypt_share(plaintext.to_vec()),
    //     follower.encrypt_share(plaintext.to_vec())
    // )
    // .unwrap();

    // log!("futures resolved");

    // // Approach 2: using spawn_local() causes a deadlock
    let (tx1, rx1) = oneshot::channel();
    let (tx2, rx2) = oneshot::channel();
    let fut1 = async move {
        let res = leader.encrypt_share(plaintext.to_vec()).await.unwrap();
        log!("here 1");
        _ = tx1.send(res).unwrap();
    };
    spawn_local(fut1);

    let fut2 = async move {
        let res = follower.encrypt_share(plaintext.to_vec()).await.unwrap();
        log!("here 2");
        _ = tx2.send(res).unwrap();
    };
    spawn_local(fut2);

    log!("waiting for fut1 to resolve");

    let val1 = rx1.await.unwrap();

    log!("resolved 1");

    let val2 = rx2.await.unwrap();

    log!("resolved 2");

    let (leader_share, follower_share) = (val1, val2);

    // let expected = aes128(key, plaintext);

    // let result: [u8; 16] = std::array::from_fn(|i| leader_share[i] ^ follower_share[i]);

    // assert_eq!(result, expected);
}
