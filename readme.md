This repo is a fork of https://github.com/tlsnotary/tlsn-js

A test was added to wasm/prover/tests/web.rs which deadlocks when trying to join two futures.

To reproduce, run

```
cd wasm/prover
wasm-pack test --firefox --release --headles
```

After ~20 secs there will be an error caused by a timeout.