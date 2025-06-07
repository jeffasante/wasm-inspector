

./target/debug/wasm-inspector ./test-wasm/target/wasm32-unknown-unknown/release/test_wasm.wasm



# JSON output (great for APIs)
./target/debug/wasm-inspector ./test-wasm/target/wasm32-unknown-unknown/release/test_wasm.wasm --format json

# Performance-only analysis
./target/debug/wasm-inspector ./test-wasm/target/wasm32-unknown-unknown/release/test_wasm.wasm --performance-only

# Security-only analysis

./target/debug/wasm-inspector ./test-wasm/target/wasm32-unknown-unknown/release/test_wasm.wasm --security-only

# Save results to file
./target/debug/wasm-inspector ./test-wasm/target/wasm32-unknown-unknown/release/test_wasm.wasm --format json -o analysis.json


 ./target/debug/wasm-inspector ./test-data/change.wasm     




./target/debug/wasm-inspector  ./test-data/change.wasm  --format json -o analysis.json


./target/debug/wasm-inspector  ./test-data/wllama.wasm --format json -o analysis.json


./target/debug/wasm-inspector  ./test-data/wllama.wasm 
