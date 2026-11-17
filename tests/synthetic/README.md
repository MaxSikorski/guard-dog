# Synthetic test data

Synthetic test data. Not a recording of any real machine. Every secret-looking value here is a fake canary. Never copy anything from here into `fixtures/setups/`.

- `record-setup/raw/`: hand-written input for `tools/record-setup.sh --redact-dir`, with one planted canary of every kind of secret and identifier it must remove, and a set of tokens it must keep.
- `record-setup/CANARIES.txt`: every planted canary, one per line (`<kind> <value>`). The tests check that none of them survives.
- `record-setup/expected/`: what the script wrote from `raw/` with `--redact-term canaryhost-7q --redact-term canaryuser`. The golden test compares byte for byte.
- `setup/`: a small made-up setup (`source = "synthetic"`) for testing Judge A's scorer.

## record-setup-realistic/

An invented Umbrel docker pair (digest-pinned images, compose labels, a bind mount, ten exposed ports), a real-shaped `lncli getinfo` with its features map and a NIP-11 reply with a five-word name. The recorder must give exit 0 on it (`regression5_realistic_umbrel_recording_exits_0`). All values are made up.
