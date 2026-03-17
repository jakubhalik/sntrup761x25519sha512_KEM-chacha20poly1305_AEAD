# this is weird but gotta use this when running cargo tests so I can run a test after test, but the tests are absolutely not gonna run on a single thread, no , not if parallelism is implemented in them, so the funny thing is that to get to test parallelism that i implemented well, I have to use command that says one thread in it, but that is just stupid semantic cargo team decision, if i did not use this all tests would try to run unconditionally in parallel , but if my tests are supposed check how many times will for example 2 endpoints mating happen on a single core vs how many when using tokio than running just `cargo test` would return super flawed results, because all the cores would be used running diff tests when trying to measure how quickly does how much of a thing happen when i run it on all cores
testSequentially () {
	cargo test --release -- --nocapture --test-threads=1 $@
}
testseq() {testSequentially $@}
seqtest() {testSequentially $@}

