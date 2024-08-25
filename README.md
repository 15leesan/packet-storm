# A solution to the [packet-storm](https://www.coretechsec.com/operation-packet-storm) challenge

This was very much a "read through file formats and follow along" attempt,
though is still quite fast - a full run on the whole dataset takes ~40ms.

## How to run

Rust is required - it's recommended to install through [rustup](https://rustup.rs/).

After that, a simple `cargo run --release` is enough, assuming that the
file `packet-storm.pcap` is in the current working directory.
Alternatively, you can use `cargo run --release -- /path/to/packet-storm.pcap`.

## Dependencies

The only dependencies are `anyhow` and `fs-err`, and are both used for
simple error handling and reporting. The `bf-runner` binary also uses `tap`
for inline conversions.

No dependencies on `libpcap` or anything similar is required - all parsing code
is included in `src/`.

# Alternative implementation

Check out [bf-runner/README.md](bf-runner/README.md) for an explanation of
`program.bf`, an implementation of this in [brainfuck](https://en.wikipedia.org/wiki/Brainfuck).
