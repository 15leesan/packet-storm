# A solution to the packet storm challenge, written in brainfuck\*

This directory contains an implementation of
the packet storm pcap parser done entirely in brainfuck. The code was (broadly
speaking) translated from the implementation at the root of this repo, though
of course several major changes had to be made.

It performs _no validation_ of the input file, and blindly assumes that data is
as expected - for a not-up-to-date list of what assumptions it makes, see the
comment at the top of `main.rs`. As a general rule, any `.pcap` file that does not
trip an assertion in the main implementation will work here, but that is not guaranteed.

The output brainfuck program is approx. ~20kchars long.

Running `cargo run -r -p bf-runner` will both update `program.bf` and attempt to run it on
`packet-storm.pcap` - I'd recommend `Ctrl-C`ing out, as it takes a long time, and is not a
particularly fast interpreter.

*Technically not written directly in brainfuck, but it compiles down to a pure-bf program.

## Output

The output is of the following form:

```
Total IP-level data: 10496 bytes
11 UDP, 74 TCP
Average of 123 bytes/packet
Most popular destination was 196.66.61.205 with 9 packets
```

The IP-level data is data contained _within_ IP packets, _i.e._ excluding Ethernet+IP headers.

The average packet size not having decimals is deliberate - the division algorithm
is $O(n)$, so adding a single decimal point would 10x the division runtime, which
is already quite slow.

The final line adjusts for multiple destinations with the same packet count, as in these examples:

```
Most popular destination was 196.168.0.1 with 1 packet
Most popular destination was 196.168.0.1 with 9 packets
Most popular destinations were 196.168.0.1 and 3 others with 1 packet each
Most popular destinations were 196.168.0.1 and 1 other with 9 packets each
```

(note that plurals are only used where correct)

When multiple destinations have the same maximal packet count, the first one encountered
is the one that will be printed.

## Speed

How fast is it? It _isn't_. I have not been able to run this to completion on the main
file, as some analysis of the progress-over-time indicates that it would take about
~17 days to finish. This is using a much faster interpreter than
mine, [brainwhat](https://github.com/dmitmel/brainwhat),
with memory limits significantly increased, and running on an AMD Ryzen 9 7950X3D.

The main culprit is the IP-tracking dictionary. Adding an IP, whether unseen or
incrementing an existing count, must traverse the entire dictionary, resulting in an
(approx.) $O(n^2)$ operation.

Indeed, the regression has reported a total program runtime estimate of $t = An^B + C$,
with $t$ being the number of seconds to complete*, $n$ being the number of packets in
the file, $A = 1.06202007568 * 10^-6$, $B = 2.02695$ and $C = 0.328513$. This is based
on data captured over 70 minutes, which got through a little over 5.5% of the target
file, taking measurements of the progress every so often. The exponent being a little
over 2 indicates that a quadratic runtime is approximately correct.

The regression calculation itself is available [here](https://www.desmos.com/calculator/yvlp8qxtim).

*This only estimates the time for the _main loop_ to complete, and does not factor
in the time that the output section would take.

## Verification

The brainfuck version was run with the
command `cat packet-storm.pcap | head -c 8181862 | brainwhat program.bf > out.txt` and, after about an hour, produced
the following output:

```
Total IP-level data: 5681838 bytes
2943 UDP, 47057 TCP
Average of 113 bytes/packet
Most popular destinations were 177.114.212.134 and 5 others with 16 packets each
```

The native version was run with the
command `cat packet-storm.pcap | head -c 8181862 | target/release/packet-storm /dev/stdin` and produced the following
output:

```
Took 1.501323ms
Total IP-level data: 5681838 bytes
2943 UDP, 47057 TCP
Average of 113.64 bytes/packet
Destination IPs by frequency:
58.218.83.83    - 16
177.114.212.134 - 16
126.101.110.188 - 16
86.213.243.19   - 16
230.195.143.131 - 16
90.41.77.16     - 16
130.84.57.146   - 15
39.213.52.178   - 15
<...snip...>
```

As can be seen, the brainfuck version produces the correct results over this scale.
