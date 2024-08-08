# A solution to the packet storm challenge, written in brainfuck\*

This directory contains a (currently only _mostly_ complete) implementation of
the packet storm pcap parser done entirely in brainfuck. The code was (broadly
speaking) translated from the implementation at the root of this repo, though
of course several major changes had to be made.

It performs _no validation_ of the input file, and blindly assumes that data is
as expected - for a not-up-to-date list of what assumptions it makes, see the
comment at the top of `main.rs`. As a general rule

This will be better documented once it's fully functional.

*Technically not written directly in brainfuck, but it compiles down to a pure-bf program.

### To-do list

- [x] Read/discard header
- [x] Packet reading loop until EOF
- [x] Count total packets, number of UDP packets, total bytes transferred (at the IP layer)
- [x] """Dictionary""" of destination IPs -> packet count
- [ ] Output simple stats
- [ ] Calculate and output _average_ bytes per packet, which requires decimal division
- [ ] Test with a well-written bf interpreter to see how fast it can go (spoilers: it won't be fast)
