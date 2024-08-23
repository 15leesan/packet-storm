use std::{
    io::Cursor,
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

use bf_runner::{
    build::{
        drain,
        num::{operate, ByteSub, DecimalAdd, DecimalSub},
        offset_from, offset_to_insns, zero_cell, zero_cell_up, Buildable, Item, Loop,
    },
    Instruction, Interpreter, Program,
};
use tap::Conv;

/*

Assumptions (non-exclusive):
    Valid header
        Little endian
        Version (2, 4)
        snap_len is u16::MAX
        link_type is 1 (Ethernet)
        Correct size
    Ethernet frames
        Captured length == original length (i.e. no truncation)
        Captured length != 0
        type/length is 0x0800 i.e. IP(v4) record
    IP packet
        version is 4 (i.e. IPv4)
        Internet Header Length is 5 (i.e. no optional fields)
        Protocol is either 0x06 (TCP) or 0x11 (UDP)
    Other
        No overflows
        Upon EOF, Input instructions set cell to 0
        At least one packet

 */

fn discard_inputs_while(offset: isize) -> Item {
    Loop::new(vec![
        Instruction::Dec.into(),
        offset_to_insns(offset),
        Instruction::Input.into(),
        offset_to_insns(-offset),
    ])
    .into()
}

fn discard_header() -> Item {
    Item::Sequence(vec![
        Item::repeat(Instruction::Inc.into(), 6),
        Loop::new(vec![
            Instruction::Dec.into(),
            Instruction::Right.into(),
            Item::repeat(Instruction::Inc.into(), 4),
            Instruction::Left.into(),
        ])
        .into(),
        Instruction::Right.into(),
        discard_inputs_while(-1),
        Instruction::Left.into(),
        Item::assert_position(0, "discard header does not move head"),
    ])
    .comment("discard header", 200)
}

fn read_u16() -> Item {
    Item::Sequence(vec![
        Instruction::Input.into(),
        Instruction::Right.into(),
        Instruction::Input.into(),
    ])
}

fn read_u32() -> Item {
    Item::Sequence(vec![
        Instruction::Input.into(),
        Instruction::Right.into(),
        Instruction::Input.into(),
        Instruction::Right.into(),
        Instruction::Input.into(),
        Instruction::Right.into(),
        Instruction::Input.into(),
    ])
}

fn read_u32_le() -> Item {
    Item::Sequence(vec![
        Item::repeat(Instruction::Right.into(), 3),
        Instruction::Input.into(),
        Instruction::Left.into(),
        Instruction::Input.into(),
        Instruction::Left.into(),
        Instruction::Input.into(),
        Instruction::Left.into(),
        Instruction::Input.into(),
    ])
}

fn find_non_zero_cell_right() -> Item {
    // "Find a non-zeroed cell" from https://esolangs.org/wiki/Brainfuck_algorithms
    Item::parse("+[>[<-]<[->+<]>]>").expect("should be valid")
}

fn zero_check(offset: isize) -> Item {
    Item::Sequence(vec![
        Loop::new(vec![
            zero_cell(),
            offset_to_insns(offset),
            Instruction::Inc.into(),
            offset_to_insns(-offset),
        ])
        .into(),
        offset_to_insns(offset),
        Instruction::Dec.into(),
        offset_to_insns(-offset),
    ])
}

fn packet_loop_before_check() -> Item {
    Item::Sequence(vec![
        Item::assert_position(Positions::PACKET_LOOP_START, "packet loop start"),
        Item::repeat(Instruction::Input.into(), 12),
        zero_cell(),
        Item::repeat(Instruction::Inc.into(), 4),
        Instruction::Right.into(),
        read_u32_le(), // Read 1*4 - eth original/captured length
        zero_check(-1),
        Instruction::Right.into(),
        zero_check(-2),
        Instruction::Right.into(),
        zero_check(-3),
        Instruction::Right.into(),
        zero_check(-4),
        Item::repeat(Instruction::Left.into(), 4),
        // If zero, we have reached EOF
    ])
}

fn packet_loop_after_check() -> Item {
    fn handle_protocol() -> Item {
        Item::Sequence(vec![
            Item::assert_position(Positions::PACKET_IP_PROTOCOL, "protocol start"),
            // Either 0x06 (TCP) or 0x11 (UDP)
            Instruction::Input.into(), // Read 1 - protocol
            Item::repeat(Instruction::Dec.into(), 0x11),
            Instruction::Right.into(),
            zero_cell(),
            Instruction::Inc.into(),
            Instruction::Left.into(),
            Loop::new(vec![
                Item::Comment("if TCP".to_owned(), 160),
                // If !0 <-> protocol=0x06 <-> TCP
                Instruction::Right.into(),
                Instruction::Dec.into(),
                Instruction::Left.into(),
                zero_cell_up(),
            ])
            .indent()
            .conv::<Item>(),
            Instruction::Right.into(),
            Loop::new(vec![
                Item::Comment("else (if UDP)".to_owned(), 160),
                // If 0 <-> protocol=0x11 <-> UDP
                Instruction::Dec.into(),
                Item::add_marker("else start"),
                offset_to_insns(offset_from(Positions::PACKET_IP_PROTOCOL + 1, Positions::NO_UDP)),
                operate::<DecimalAdd<{ Positions::NO_UDP_WIDTH }>>(offset_from(Positions::NO_UDP, Positions::SCRATCH_SPACE_START)),
                offset_to_insns(offset_from(Positions::NO_UDP, Positions::PACKET_IP_PROTOCOL + 1)),
                Item::assert_marker_offset("else start", 0, "branch end"),
                Item::remove_marker("else start"),
            ])
            .indent()
            .conv::<Item>(),
            Instruction::Left.into(),
        ])
        .comment("handle protocol", 100)
    }

    fn handle_total_length() -> Item {
        fn collapse_condition() -> Item {
            Item::Sequence(vec![
                Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_START, "collapse total length call"),
                Instruction::Right.conv::<Item>().repeat(2),
                zero_cell(),
                Instruction::Right.into(),
                zero_cell(),
                Instruction::Left.conv::<Item>().repeat(3),
                Loop::new(vec![
                    drain(&[2], true),
                    Instruction::Right.conv::<Item>().repeat(3),
                    Instruction::Inc.into(),
                    Instruction::Left.conv::<Item>().repeat(3),
                ])
                .into(),
                Instruction::Right.conv::<Item>().repeat(2),
                drain(&[-2], true),
                Instruction::Left.conv::<Item>().repeat(1),
                Loop::new(vec![
                    drain(&[1], true),
                    Instruction::Right.conv::<Item>().repeat(2),
                    Instruction::Inc.into(),
                    Instruction::Left.conv::<Item>().repeat(2),
                ])
                .into(),
                Instruction::Right.into(),
                drain(&[-1], true),
                Instruction::Right.into(),
                Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_SCRATCH + 1, "flag of length left non-zero"),
            ])
        }

        Item::Sequence(vec![
            Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_START, "total length call"),
            Instruction::Right.conv::<Item>().repeat(4),
            Instruction::Inc.conv::<Item>().repeat(20),
            Loop::new(vec![
                Instruction::Left.conv::<Item>().repeat(3),
                operate::<ByteSub<2>>(1),
                Instruction::Right.conv::<Item>().repeat(3),
                Instruction::Dec.into(),
            ])
            .into(),
            Instruction::Left.conv::<Item>().repeat(4),
            collapse_condition(),
            Loop::new(vec![
                Instruction::Input.into(),
                zero_cell(),
                Instruction::Left.conv::<Item>().repeat(2),
                Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH, "packet IP length sub"),
                operate::<ByteSub<2>>(1),
                Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH, "before transport bytes inc"),
                offset_to_insns(offset_from(Positions::PACKET_IP_TOTAL_LENGTH, Positions::TRANSPORT_BYTES)),
                operate::<DecimalAdd<{ Positions::TRANSPORT_BYTES_WIDTH }>>(offset_from(Positions::TRANSPORT_BYTES, Positions::SCRATCH_SPACE_START)),
                offset_to_insns(offset_from(Positions::TRANSPORT_BYTES, Positions::PACKET_IP_TOTAL_LENGTH_START)),
                Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_START, "after transport bytes inc"),
                collapse_condition(),
            ])
            .indent()
            .into(),
        ])
    }

    Item::Sequence(vec![
        Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_START, "inc packet count"),
        offset_to_insns(offset_from(Positions::PACKET_IP_TOTAL_LENGTH_START, Positions::NO_PACKETS)),
        operate::<DecimalAdd<{ Positions::NO_PACKETS_WIDTH }>>(offset_from(Positions::NO_PACKETS, Positions::SCRATCH_SPACE_START)),
        offset_to_insns(offset_from(Positions::NO_PACKETS, Positions::PACKET_IP_TOTAL_LENGTH_START)),
        Item::repeat(Instruction::Input.into(), 2 * 6 + 2 + 2),
        Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_START, "packet ip total length start"),
        read_u16(), // Read 1*2 - ip total length
        Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH, "packet ip total length"),
        Instruction::Right.conv::<Item>().repeat(3), // Scratch cells
        Instruction::Right.into(),
        Item::repeat(Instruction::Input.into(), 5),
        handle_protocol(),
        Item::repeat(Instruction::Input.into(), 2),
        Item::repeat(Instruction::Input.into(), 4), // Discard source addr
        // Read 2*4 - dest addr
        Item::assert_position(Positions::PACKET_IP_DEST_START - 10, "before IP"),
        offset_to_insns(10),
        read_u32(),
        Item::assert_position(Positions::PACKET_IP_DEST, "packet ip dest"),
        offset_to_insns(offset_from(Positions::PACKET_IP_DEST, Positions::PACKET_IP_DEST_START)),
        append_to_list(),
        Item::assert_position(Positions::LIST_HEADSTOP + 2, "after list add"),
        offset_to_insns(offset_from(
            Positions::LIST_HEADSTOP + 2,
            Positions::PACKET_IP_TOTAL_LENGTH_START,
        )),
        handle_total_length(),
        Item::assert_position(Positions::PACKET_IP_TOTAL_LENGTH_SCRATCH + 1, "total length done"),
        offset_to_insns(offset_from(
            Positions::PACKET_IP_TOTAL_LENGTH_SCRATCH + 1,
            Positions::PACKET_LOOP_START,
        )),
        Item::Comment("end of packet".to_owned(), 190),
    ])
}

fn read_packet_loop() -> Item {
    Item::Sequence(vec![
        packet_loop_before_check().comment("before check", 180),
        Loop::new(vec![
            packet_loop_after_check().comment("after check", 180),
            packet_loop_before_check().comment("before check", 180),
        ])
        .indent()
        .into(),
    ])
}

struct Positions;

impl Positions {
    const SCRATCH_SPACE_START: usize = 0;
    const SCRATCH_SPACE: usize = Self::SCRATCH_SPACE_START + 3;

    const NO_PACKETS_START: usize = Self::SCRATCH_SPACE + 1;
    const NO_PACKETS: usize = Self::NO_PACKETS_START + (Self::NO_PACKETS_WIDTH - 1);
    const NO_PACKETS_WIDTH: usize = 7;

    const NO_UDP_START: usize = Self::NO_PACKETS + 2;
    const NO_UDP: usize = Self::NO_UDP_START + (Self::NO_UDP_WIDTH - 1);
    const NO_UDP_WIDTH: usize = 7;

    const TRANSPORT_BYTES_START: usize = Self::NO_UDP + 2;
    const TRANSPORT_BYTES: usize = Self::TRANSPORT_BYTES_START + (Self::TRANSPORT_BYTES_WIDTH - 1);
    const TRANSPORT_BYTES_WIDTH: usize = 9;

    const PACKET_LOOP_START: usize = Self::TRANSPORT_BYTES + 2;

    const PACKET_IP_TOTAL_LENGTH_START: usize = Self::PACKET_LOOP_START;
    const PACKET_IP_TOTAL_LENGTH: usize = Self::PACKET_IP_TOTAL_LENGTH_START + 1;
    const PACKET_IP_TOTAL_LENGTH_SCRATCH: usize = Self::PACKET_IP_TOTAL_LENGTH + 1; // 3 cells

    const PACKET_IP_PROTOCOL: usize = Self::PACKET_IP_TOTAL_LENGTH_SCRATCH + 3;

    // As protocol is overwritten
    const PACKET_IP_DEST_START: usize = Self::PACKET_IP_PROTOCOL + 10; // 10-space required for division space
    const PACKET_IP_DEST: usize = Self::PACKET_IP_DEST_START + 3;

    const LIST_HEADSTOP: usize = Self::PACKET_IP_DEST + 1;
    const SECONDARY_IP_STORED_START: usize = Self::LIST_HEADSTOP + 2;
    const LIST_START: usize = Self::LIST_HEADSTOP + ListEntry::WIDTH;

    const GREATER_FLAG: usize = Self::LIST_HEADSTOP - 1;
    const GENERAL_COUNT: usize = Self::GREATER_FLAG - 1;
    const LIST_LOOP_FLAG: usize = Self::GENERAL_COUNT - 1;
    const FOUND_IP: usize = Self::LIST_LOOP_FLAG - 4;
    const TARGET_COUNT: usize = Self::FOUND_IP - 1;
    const TEXT_SPACE: usize = Self::TARGET_COUNT - 8;
}

fn setup_state() -> Item {
    assert_eq!(Positions::NO_PACKETS + 2, Positions::NO_UDP_START);
    assert_eq!(Positions::NO_UDP + 2, Positions::TRANSPORT_BYTES_START);

    Item::Sequence(vec![
        Item::assert_position(0, "after header discard"),
        offset_to_insns(offset_from(0, Positions::NO_PACKETS_START)),
        Item::Sequence(vec![
            Instruction::Dec.into(),
            Instruction::Dec.into(),
            Instruction::Right.into(),
        ])
        .repeat(Positions::NO_PACKETS_WIDTH + Positions::NO_UDP_WIDTH + Positions::TRANSPORT_BYTES_WIDTH + 2),
        Instruction::Right.into(),
        Instruction::Inc.conv::<Item>().repeat(4),
        Loop::new(vec![
            Instruction::Left.into(),
            Instruction::Left.into(),
            Loop::new(vec![Instruction::Dec.into(), Instruction::Left.into()]).into(),
            Item::assert_position(Positions::NO_PACKETS_START - 1, "left"),
            Instruction::Right.into(),
            Loop::new(vec![Instruction::Dec.into(), Instruction::Right.into()]).into(),
            Instruction::Right.into(),
            Instruction::Dec.into(),
            Item::assert_position(Positions::TRANSPORT_BYTES + 2, "right"),
        ])
        .indent()
        .into(),
        Item::assert_position(Positions::TRANSPORT_BYTES + 2, "add gaps"),
        offset_to_insns(offset_from(Positions::TRANSPORT_BYTES + 2, Positions::NO_PACKETS + 1)),
        zero_cell_up(),
        offset_to_insns(offset_from(Positions::NO_PACKETS + 1, Positions::NO_UDP + 1)),
        zero_cell_up(),
        Item::assert_position(Positions::NO_UDP + 1, "done"),
        offset_to_insns(offset_from(Positions::NO_UDP + 1, Positions::PACKET_LOOP_START)),
    ])
    .comment("setup state", 250)
}

#[allow(dead_code)] // Groups related constants under an unused struct
struct ListEntry;

impl ListEntry {
    const EXIST_FLAG: usize = 0;
    const MARKED_FLAG: usize = Self::EXIST_FLAG + 1;
    const SCRATCH: usize = Self::MARKED_FLAG + 1;
    const SCRATCH_WIDTH: usize = 2;

    const COUNT: usize = Self::SCRATCH + Self::SCRATCH_WIDTH;

    const DATA_START: usize = Self::COUNT + 1;
    const DATA_WIDTH: usize = 4;
    const DATA_END: usize = Self::DATA_START + Self::DATA_WIDTH - 1;

    const WIDTH: usize = Self::DATA_END + 1;
}

fn append_to_list() -> Item {
    fn distribute(offset: usize, restore: bool) -> Item {
        let start_base;
        let to_base;
        let insn;

        if restore {
            start_base = Positions::SECONDARY_IP_STORED_START;
            to_base = Positions::PACKET_IP_DEST_START;
            insn = Instruction::Inc;
        } else {
            start_base = Positions::PACKET_IP_DEST_START;
            to_base = Positions::SECONDARY_IP_STORED_START;
            insn = Instruction::Dec;
        }

        Item::Sequence(vec![
            Item::assert_position(start_base + offset, "[re]distribute start"),
            Loop::new(vec![
                Instruction::Dec.into(),
                offset_to_insns(offset_from(start_base + offset, to_base + offset)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(to_base + offset, Positions::LIST_START)),
                Loop::new(vec![
                    offset_to_insns((ListEntry::DATA_START + offset) as _),
                    insn.into(),
                    offset_to_insns((ListEntry::WIDTH - ListEntry::DATA_START - offset) as _),
                ])
                .into(),
                offset_to_insns(-(ListEntry::WIDTH as isize)),
                Loop::new(vec![offset_to_insns(-(ListEntry::WIDTH as isize))]).into(),
                Item::assert_position(Positions::LIST_HEADSTOP, "return to list head"),
                offset_to_insns(offset_from(Positions::LIST_HEADSTOP, start_base + offset)),
            ])
            .indent()
            .conv::<Item>()
            .comment(format!("[re]distribute {offset}"), 80),
        ])
    }

    fn accumulate_zero(offset: usize) -> Item {
        Item::Sequence(vec![
            Item::assert_marker_offset("current zero target", (ListEntry::DATA_START + offset) as _, "target octet"),
            Loop::new(vec![
                Instruction::Dec.into(),
                offset_to_insns(offset_from(ListEntry::DATA_START + offset, ListEntry::SCRATCH + 1)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(ListEntry::SCRATCH + 1, ListEntry::MARKED_FLAG)),
                zero_cell(),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(ListEntry::MARKED_FLAG, ListEntry::DATA_START + offset)),
            ])
            .indent()
            .conv::<Item>(),
            offset_to_insns(offset_from(ListEntry::DATA_START + offset, ListEntry::MARKED_FLAG)),
            drain(&[1], true),
            offset_to_insns(offset_from(ListEntry::MARKED_FLAG, ListEntry::SCRATCH + 1)),
            drain(&[offset_from(ListEntry::SCRATCH + 1, ListEntry::DATA_START + offset)], true),
            offset_to_insns(offset_from(ListEntry::SCRATCH + 1, ListEntry::DATA_START + offset)),
            Item::assert_marker_offset(
                "current zero target",
                (ListEntry::DATA_START + offset) as _,
                "after target octet",
            ),
        ])
    }

    fn copy_over(offset: usize) -> Item {
        Item::Sequence(vec![
            Item::assert_position(Positions::LIST_HEADSTOP, "copy over"),
            offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::PACKET_IP_DEST_START + offset)),
            Loop::new(vec![
                Instruction::Dec.into(),
                offset_to_insns(offset_from(Positions::PACKET_IP_DEST_START + offset, Positions::LIST_START)),
                Loop::new(vec![offset_to_insns(ListEntry::WIDTH as _)]).into(),
                Item::assert_marker_offset("new entry", ListEntry::WIDTH as _, "found entry"),
                offset_to_insns(offset_from(ListEntry::WIDTH, ListEntry::DATA_START + offset)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(ListEntry::DATA_START + offset, ListEntry::EXIST_FLAG)),
                Loop::new(vec![offset_to_insns(-(ListEntry::WIDTH as isize))]).into(),
                Item::assert_position(Positions::LIST_HEADSTOP, "return"),
                offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::PACKET_IP_DEST_START + offset)),
            ])
            .into(),
            offset_to_insns(offset_from(Positions::PACKET_IP_DEST_START + offset, Positions::LIST_HEADSTOP)),
        ])
        .comment(format!("copy over {{offset={offset}}}"), 80)
    }

    Item::Sequence(vec![
        Item::assert_position(Positions::PACKET_IP_DEST_START, "start"),
        distribute(0, false),
        Instruction::Right.into(),
        distribute(1, false),
        Instruction::Right.into(),
        distribute(2, false),
        Instruction::Right.into(),
        distribute(3, false),
        Item::assert_position(Positions::PACKET_IP_DEST_START + 3, "after distribute"),
        offset_to_insns(offset_from(Positions::PACKET_IP_DEST_START + 3, Positions::LIST_START)),
        Loop::new(vec![
            Item::add_marker("current zero target"),
            offset_to_insns(ListEntry::DATA_START as _),
            accumulate_zero(0),
            Instruction::Right.into(),
            accumulate_zero(1),
            Instruction::Right.into(),
            accumulate_zero(2),
            Instruction::Right.into(),
            accumulate_zero(3),
            Item::assert_marker_offset("current zero target", (ListEntry::WIDTH - 1) as _, "end"),
            offset_to_insns(offset_from(ListEntry::WIDTH - 1, ListEntry::SCRATCH)),
            Item::remove_marker("current zero target"),
            Instruction::Right.into(),
            Instruction::Inc.into(),
            Instruction::Left.into(),
            Loop::new(vec![
                Instruction::Dec.into(),
                Instruction::Right.into(),
                zero_cell(),
                Instruction::Left.into(),
            ])
            .into(),
            Instruction::Right.into(),
            Loop::new(vec![
                zero_cell(),
                offset_to_insns(offset_from(ListEntry::SCRATCH + 1, ListEntry::MARKED_FLAG)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(ListEntry::MARKED_FLAG, ListEntry::COUNT)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(ListEntry::COUNT, ListEntry::WIDTH)),
                Loop::new(vec![offset_to_insns(ListEntry::WIDTH as _)]).into(),
                offset_to_insns(-(ListEntry::WIDTH as isize)),
                offset_to_insns((ListEntry::SCRATCH + 1) as _),
            ])
            .indent()
            .conv::<Item>()
            .comment("if zero (IP match)", 120),
            offset_to_insns(offset_from(ListEntry::SCRATCH + 1, ListEntry::WIDTH)),
        ])
        .indent()
        .conv::<Item>()
        .comment("check each known IP for a match", 130),
        offset_to_insns(-(ListEntry::WIDTH as isize)),
        Loop::new(vec![
            Instruction::Right.into(),
            Loop::new(vec![
                zero_cell(),
                Instruction::Left.into(),
                Loop::new(vec![offset_to_insns(-(ListEntry::WIDTH as isize))]).into(),
                Instruction::Right.into(),
                Instruction::Inc.into(),
                Instruction::Left.into(),
                offset_to_insns(offset_from(
                    Positions::LIST_HEADSTOP,
                    Positions::LIST_START + ListEntry::MARKED_FLAG,
                )),
            ])
            .into(),
            Instruction::Left.into(),
            offset_to_insns(-(ListEntry::WIDTH as isize)),
        ])
        .indent()
        .into(),
        Item::assert_position(Positions::LIST_HEADSTOP, "return to headstop"),
        offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::SECONDARY_IP_STORED_START)),
        distribute(0, true),
        Instruction::Right.into(),
        distribute(1, true),
        Instruction::Right.into(),
        distribute(2, true),
        Instruction::Right.into(),
        distribute(3, true),
        Item::assert_position(Positions::SECONDARY_IP_STORED_START + 3, "after redistribute"),
        offset_to_insns(offset_from(
            Positions::SECONDARY_IP_STORED_START + 3,
            Positions::LIST_HEADSTOP + 2,
        )),
        zero_cell(), // TODO: I *think* this is already zeroed?
        Instruction::Inc.into(),
        Instruction::Left.into(),
        Loop::new(vec![
            // Erase IP
            Instruction::Dec.into(),
            Instruction::Right.into(),
            Instruction::Dec.into(),
            offset_to_insns(offset_from(Positions::LIST_HEADSTOP + 2, Positions::PACKET_IP_DEST_START)),
            Item::Sequence(vec![zero_cell(), Instruction::Right.into()]).repeat(4),
            Instruction::Right.into(),
        ])
        .indent()
        .conv::<Item>()
        .comment("if mark (found)", 120),
        Item::assert_position(Positions::LIST_HEADSTOP + 1, "mark found"),
        Instruction::Right.into(),
        Loop::new(vec![
            zero_cell(),
            offset_to_insns(offset_from(Positions::LIST_HEADSTOP + 2, Positions::LIST_START)),
            Loop::new(vec![offset_to_insns(ListEntry::WIDTH as _)]).into(),
            Item::add_marker("new entry"),
            Instruction::Inc.into(),
            // Yes, using the 0 count to be 1 occurrence *would* work, and would let us
            // show counts of up to 256 instead of 255, but it makes writing the
            // maximum finder more complicated (or at least annoying), so we'll just
            // have to live with it like this.
            offset_to_insns(offset_from(ListEntry::EXIST_FLAG, ListEntry::COUNT)),
            Instruction::Inc.into(),
            offset_to_insns(offset_from(ListEntry::COUNT, ListEntry::EXIST_FLAG)),
            Loop::new(vec![offset_to_insns(-(ListEntry::WIDTH as isize))]).into(),
            copy_over(0),
            copy_over(1),
            copy_over(2),
            copy_over(3),
            Item::remove_marker("new entry"),
            Item::assert_position(Positions::LIST_HEADSTOP, "after copy_over"),
            offset_to_insns(2),
        ])
        .indent()
        .conv::<Item>()
        .comment("else (new)", 120),
        Item::assert_position(Positions::LIST_HEADSTOP + 2, "mark not found"),
    ])
}

// TEMP: move into `output()`

// Positioned on the first cell of the number
// Cannot be called on cell 0
// TODO: It outputs a trailing null byte that it shouldn't
fn display_decimal(width: usize, extra_gap: usize) -> Item {
    let mark = "display start";
    Item::Sequence(vec![
        Item::add_marker(mark),
        offset_to_insns(2 * width as isize + extra_gap as isize),
        Instruction::Right.into(),
        Instruction::Inc.conv::<Item>().repeat(8),
        Loop::new(vec![
            Instruction::Dec.into(),
            Instruction::Left.into(),
            Instruction::Inc.conv::<Item>().repeat(6),
            Instruction::Right.into(),
        ])
        .into(),
        Instruction::Left.into(),
        Loop::new(vec![
            Instruction::Dec.into(),
            Item::Sequence(vec![Instruction::Right.into(), Instruction::Inc.into()]).repeat(width),
            Instruction::Left.conv::<Item>().repeat(width),
        ])
        .into(),
        Item::assert_marker_offset(mark, 2 * width as isize + extra_gap as isize, "init output end"),
        offset_to_insns(offset_from(2 * width + extra_gap, 2 * width)),
        Instruction::Dec.into(),
        offset_to_insns(offset_from(2 * width, width - 1)),
        Item::Sequence(vec![
            Loop::new(vec![
                Instruction::Dec.into(),
                offset_to_insns(width as isize),
                zero_cell(),
                Instruction::Inc.into(),
                offset_to_insns(width as isize + 1 + extra_gap as isize),
                Instruction::Inc.into(),
                offset_to_insns(-(2 * width as isize + 1 + extra_gap as isize)),
            ])
            .into(),
            Instruction::Left.into(),
        ])
        .repeat(width)
        .comment("leading zeros filter", 120),
        Item::assert_marker_offset(mark, -1, "after transport bytes leading zeros"),
        find_non_zero_cell_right(),
        Instruction::Left.into(),
        Instruction::Inc.into(),
        Loop::new(vec![
            Instruction::Right.into(),
            offset_to_insns(width as isize + 1 + extra_gap as isize),
            Instruction::Output.into(),
            offset_to_insns(-(width as isize + 1 + extra_gap as isize)),
            Instruction::Inc.into(),
        ])
        .into(),
        Item::Sequence(vec![
            Item::Sequence(vec![Instruction::Left.into(), zero_cell()]).repeat(width + 1),
            find_non_zero_cell_right(),
            Item::assert_marker_offset(
                mark,
                2 * width as isize + 1 + extra_gap as isize,
                "begin restore transport bytes",
            ),
            Instruction::Left.conv::<Item>().repeat(2),
            Instruction::Inc.conv::<Item>().repeat(8),
            Loop::new(vec![
                Instruction::Dec.into(),
                Instruction::Right.into(),
                Instruction::Inc.conv::<Item>().repeat(6),
                Instruction::Left.into(),
            ])
            .into(),
            Instruction::Right.into(),
            Loop::new(vec![
                Instruction::Dec.into(),
                Item::Sequence(vec![Instruction::Right.into(), Instruction::Dec.into()]).repeat(width),
                Instruction::Left.conv::<Item>().repeat(width),
            ])
            .into(),
            // Item::Sequence(vec![
            //     Instruction::Right.into(),
            //     Instruction::Inc.into(),
            //     Instruction::Left.into(),
            // ])
            // .comment("TEMP: only for vis", 250),
            Instruction::Left.conv::<Item>().repeat(2 * width + extra_gap),
        ])
        .comment("decimal cleanup", 120),
        Item::assert_marker_offset(mark, 0, "decimal reset"),
        Item::remove_marker(mark),
    ])
    .comment(format!("display decimal {{width={width}}}"), 180)
}

fn output() -> anyhow::Result<Item> {
    #[derive(Debug)]
    enum Text {
        TransportLevelData,
        BytesNewline,
        UDP,
        TCPNewline,
        BytesPerPacket,
        MostPopular,
        DestinationWas,
        DestinationsWere,
        And,
        Other,
        With,
        Packet,
        Each,
        Newline,
    }

    fn write_text(text: Text) -> Item {
        // Text output code generated with https://tnu.me/brainfuck/generator
        let marker = format!("write text {text:?}");
        let v = match text {
            Text::TransportLevelData => {
                vec![
                    Item::parse(
                        "++++++++[>+++++++++++>++++++++++++++>++++++++++++>++++>++++++>+++++++<<<<<<-]\
        >----.>-.+++++.>+.<--------.>>.<<++++++++.--.>.<----.+++++.---.-.+++.++.>>>---.<<<--------.\
        >++++.<++++++++++.>.+++++++.>.<--------.---.<--.>.>>>++.<<.",
                    )
                    .expect("should be valid")
                    .comment("write \"Total transport-level data: \"", 220),
                    Item::assert_marker_offset(marker.clone(), 4, "after text write"),
                    Instruction::Right.conv::<Item>().repeat(2),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::BytesNewline => {
                vec![
                    Item::parse("++++++++[>++++>++++++++++++>+++++++++++++++>+<<<<-]>.>++.>+.-----.<+++.>-.>++.")
                        .expect("should be valid")
                        .comment("write \" bytes\\n\"", 220),
                    Item::assert_marker_offset(marker.clone(), 4, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::UDP => {
                vec![
                    Item::parse("+++++++[>+++++>++++++++++++>++++++++++>++++++<<<<-]>---.>+.>--.<-----.>>++.<<<.")
                        .expect("should be valid")
                        .comment("write \" UDP, \"", 220),
                    Item::assert_marker_offset(marker.clone(), 1, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Right.into()]).into(),
                    offset_to_insns(-5),
                ]
            }
            Text::TCPNewline => {
                vec![
                    Item::parse("+++++++[>+++++>++++++++++++>++++++++++>+<<<<-]>---.>.>---.<----.>>+++.")
                        .expect("should be valid")
                        .comment("write \" TCP\\n\"", 220),
                    Item::assert_marker_offset(marker.clone(), 4, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::BytesPerPacket => {
                vec![
                    Item::parse(
                        "+++++++[>+++++>++++++++++++++>+++++++++++++++++>+++++++>+<<<<<-]>---.>.>\
                    ++.-----.<+++.>-.>--.<---.<----.++.>-----.<++.>+++++++++.>>+++.",
                    )
                    .expect("should be valid")
                    .comment("write \" bytes/packet\\n\"", 220),
                    Item::assert_marker_offset(marker.clone(), 5, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::MostPopular => {
                vec![
                    Item::parse(
                        "++++++++++[>++++++++>+++++++++++>+++>++++++++++>++++++++++<<<<<-]>---.\
                        >+.++++.+.>++.<----.-.+.+++++.---------.>>---.<<++++++.>.>>.+.<<<+.+.>>>++++\
                        .+++++.<.<<.>>>-----.++++++.-.",
                    )
                    .expect("should be valid")
                    .comment("write \"Most popular destination\"", 220),
                    Item::assert_marker_offset(marker.clone(), 5, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::DestinationWas => {
                vec![
                    Item::parse("++++++++++[>+++>++++++++++++>++++++++++<<<-]>++.>-.>---.<----.<.")
                        .expect("should be valid")
                        .comment("write \" was \"", 220),
                    Item::assert_marker_offset(marker.clone(), 1, "after text write"),
                    offset_to_insns(2),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::DestinationsWere => {
                vec![
                    Item::parse(
                        "++++++++++[>++++++++++++>+++>++++++++++<<<-]>-----.>++.<++++.\
                    >>+.<<-----.>>.<.",
                    )
                    .expect("should be valid")
                    .comment("write \"s were \"", 220),
                    Item::assert_marker_offset(marker.clone(), 2, "after text write"),
                    offset_to_insns(1),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::And => {
                vec![
                    Item::parse("++++++++++[>+++>++++++++++>+++++++++++<<<-]>++.>---.>.<+++.<.")
                        .expect("should be valid")
                        .comment("write \" and \"", 220),
                    Item::assert_marker_offset(marker.clone(), 1, "after text write"),
                    offset_to_insns(2),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::Other => {
                vec![
                    Item::parse("++++++++++[>+++>+++++++++++>++++++++++<<<-]>++.>+.+++++.>++++.---.<--.")
                        .expect("should be valid")
                        .comment("write \" other\"", 220),
                    Item::assert_marker_offset(marker.clone(), 2, "after text write"),
                    offset_to_insns(1),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::With => {
                vec![
                    Item::parse("++++++++++[>+++>++++++++++++>+++++++++++<<<-]>++.>-.>-----.<---.>-.<<.")
                        .expect("should be valid")
                        .comment("write \" with \"", 220),
                    Item::assert_marker_offset(marker.clone(), 1, "after text write"),
                    offset_to_insns(2),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::Packet => {
                vec![
                    Item::parse("++++++++++[>+++>+++++++++++>++++++++++<<<-]>++.>++.>---.++.<-----.>++.<+++++++++.")
                        .expect("should be valid")
                        .comment("write \" packet\"", 220),
                    Item::assert_marker_offset(marker.clone(), 2, "after text write"),
                    offset_to_insns(1),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::Each => {
                vec![
                    Item::parse("++++++++[>++++>+++++++++++++<<-]>.>---.----.++.+++++.")
                        .expect("should be valid")
                        .comment("write \" each\"", 220),
                    Item::assert_marker_offset(marker.clone(), 2, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
            Text::Newline => {
                vec![
                    Item::parse("+++[>+++<-]>+.").expect("should be valid").comment("write \"\\n\"", 220),
                    Item::assert_marker_offset(marker.clone(), 1, "after text write"),
                    Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
                ]
            }
        };
        Item::Sequence(vec![
            Item::add_marker(marker.clone()),
            Item::Sequence(v),
            Item::assert_marker_offset(marker.clone(), 0, "after text cleanup"),
            Item::remove_marker(marker),
        ])
    }

    fn divide() -> Item {
        fn new_zero_check(temp_copy: isize, accumulator: isize) -> Item {
            Item::Sequence(vec![
                Loop::new(vec![
                    Instruction::Dec.into(),
                    offset_to_insns(temp_copy),
                    Instruction::Inc.into(),
                    offset_to_insns(-temp_copy),
                    offset_to_insns(accumulator),
                    Instruction::Inc.into(),
                    offset_to_insns(-accumulator),
                ])
                .into(),
                offset_to_insns(temp_copy),
                drain(&[-temp_copy], true),
                offset_to_insns(-temp_copy),
            ])
        }

        // On the last cell of the number
        fn zero_check_number(width: usize, temp_copy: isize, accumulator: isize) -> Item {
            let s = (0..width)
                .flat_map(|i| [new_zero_check(temp_copy + i as isize, accumulator + i as isize), Instruction::Left.into()])
                .collect();

            Item::Sequence(vec![
                offset_to_insns(accumulator),
                zero_cell(),
                offset_to_insns(-accumulator),
                Item::Sequence(s),
                offset_to_insns(width as _),
            ])
            .comment(format!("zero check number {{width={width}}}"), 120)
        }

        const ZC: usize = 0;
        const SC: usize = 1;

        /*
        N - number (decimal 9)
        D - divisor (decimal 7)
        T - temporary storage (decimal 7)
        Q - quotient (decimal 9)
         */

        const NW: usize = Positions::TRANSPORT_BYTES_WIDTH;
        const N: usize = SC + 2 + NW - 1; // = 11
        const N0: usize = N + 1;

        const DW: usize = Positions::NO_PACKETS_WIDTH;
        const D: usize = N0 + DW; // = 19
        const D0: usize = D + 1;

        const TW: usize = DW;
        const T: usize = D0 + TW;
        const T0: usize = T + 1;

        const QW: usize = NW;
        const Q: usize = T0 + QW;
        const Q0: usize = Q + 1;

        Item::Sequence(vec![
            Item::assert_position(0, "before division"),
            offset_to_insns(offset_from(0, N)),
            Item::assert_marker_offset("divide N", 0, "N correctly positioned"),
            offset_to_insns(offset_from(N, D)),
            Item::assert_marker_offset("divide D", 0, "D correctly positioned"),
            offset_to_insns(offset_from(D, 0)),
            offset_to_insns(offset_from(0, T0)),
            Instruction::Inc.conv::<Item>().repeat(10),
            Loop::new(vec![
                Instruction::Dec.into(),
                Item::Sequence(vec![Instruction::Left.into(), Instruction::Dec.into()]).repeat(TW),
                Instruction::Right.conv::<Item>().repeat(TW),
            ])
            .into(),
            Item::assert_position(T0, "after init"),
            offset_to_insns(offset_from(T0, 0)),
            offset_to_insns(offset_from(0, Q0)),
            Instruction::Inc.conv::<Item>().repeat(10),
            Loop::new(vec![
                Instruction::Dec.into(),
                Item::Sequence(vec![Instruction::Left.into(), Instruction::Dec.into()]).repeat(QW),
                offset_to_insns(QW as _),
            ])
            .into(),
            Item::assert_position(Q0, "Q setup"),
            offset_to_insns(offset_from(Q0, 0)),
            // Setup complete, at cell 0
            offset_to_insns(offset_from(0, N)),
            zero_check_number(NW, offset_from(N, SC), offset_from(N, ZC)),
            Item::assert_position(N, "still here"),
            offset_to_insns(offset_from(N, ZC)),
            Loop::new(vec![
                zero_cell(),
                offset_to_insns(offset_from(ZC, N)),
                operate::<DecimalSub<NW>>(offset_from(N, ZC)),
                Item::assert_position(N, "after N subtract"),
                offset_to_insns(offset_from(N, ZC)),
                zero_cell(),
                offset_to_insns(offset_from(ZC, D)),
                operate::<DecimalSub<DW>>(offset_from(D, ZC)),
                Item::assert_position(D, "after D subtract"),
                zero_check_number(DW, offset_from(D, SC), offset_from(D, ZC)),
                offset_to_insns(offset_from(D, ZC)),
                drain(&[offset_from(ZC, N0)], true),
                offset_to_insns(offset_from(ZC, T)),
                operate::<DecimalAdd<TW>>(offset_from(T, ZC)),
                Item::assert_position(T, "after T add"),
                offset_to_insns(offset_from(T, N0)),
                drain(&[offset_from(N0, ZC)], true),
                offset_to_insns(offset_from(N0, ZC)),
                Instruction::Right.into(),
                zero_cell(),
                Instruction::Inc.into(),
                Instruction::Left.into(),
                // If nonzero (i.e. d != 0)
                Loop::new(vec![
                    zero_cell(),
                    Instruction::Right.into(),
                    zero_cell(),
                    Instruction::Left.into(),
                ])
                .into(),
                Instruction::Right.into(),
                Item::assert_position(ZC + 1, "before else"),
                // Else (i.e. d == 0)
                Loop::new(vec![
                    zero_cell(),
                    offset_to_insns(offset_from(ZC + 1, T)),
                    Item::Sequence(vec![drain(&[offset_from(T, D)], true), Instruction::Left.into()]).repeat(TW),
                    Item::assert_position(D + 1, "after restore D"),
                    offset_to_insns(offset_from(D + 1, T0)),
                    Instruction::Inc.conv::<Item>().repeat(10),
                    Loop::new(vec![
                        Instruction::Dec.into(),
                        Item::Sequence(vec![Instruction::Left.into(), Instruction::Dec.into()]).repeat(TW),
                        Instruction::Left.into(),
                        Item::Sequence(vec![Instruction::Left.into(), Instruction::Inc.into()]).repeat(DW),
                        Instruction::Right.conv::<Item>().repeat(TW + DW + 1),
                    ])
                    .into(),
                    Item::assert_position(T0, "after unreset T+D"),
                    offset_to_insns(offset_from(T0, Q)),
                    operate::<DecimalAdd<QW>>(offset_from(Q, ZC)),
                    Item::assert_position(Q, "after increment Q"),
                    offset_to_insns(offset_from(Q, ZC + 1)),
                ])
                .into(),
                offset_to_insns(offset_from(ZC + 1, N)),
                zero_check_number(NW, offset_from(N, SC), offset_from(N, ZC)),
                Item::assert_position(N, "before loop"),
                offset_to_insns(offset_from(N, ZC)),
            ])
            .into(),
            offset_to_insns(offset_from(ZC, Q0)),
            Instruction::Inc.conv::<Item>().repeat(10),
            Loop::new(vec![
                Instruction::Dec.into(),
                Item::Sequence(vec![Instruction::Left.into(), Instruction::Inc.into()]).repeat(QW),
                offset_to_insns(QW as _),
            ])
            .into(),
            Item::assert_position(Q0, "Q desetup"),
            offset_to_insns(-(QW as isize)),
            display_decimal(QW, 0),
            Item::assert_position(Q - QW + 1, "after division"),
            offset_to_insns(offset_from(Q - QW + 1, 0)),
        ])
    }

    fn list_pass(pass_name: &'static str, perform: impl FnOnce(Rc<AtomicBool>) -> Item) -> Item {
        let brk = Rc::new(AtomicBool::new(false));
        let brk2 = Rc::clone(&brk);
        let brk3 = Rc::clone(&brk);
        let perform = perform(Rc::clone(&brk));
        let current_marker = "current item";
        Item::Sequence(vec![
            Item::assert_position(Positions::LIST_START, pass_name),
            Item::custom(move |_, _, _| brk2.store(false, Ordering::SeqCst)),
            Loop::new(vec![
                Item::add_marker(current_marker),
                perform,
                Item::custom(move |tape, position, markers| {
                    if brk.load(Ordering::SeqCst) {
                        Item::assert_marker_offset("list end", ListEntry::WIDTH as isize, "break").run(tape, position, markers)
                    } else {
                        Item::assert_marker_offset(current_marker, ListEntry::WIDTH as isize, "after perform").run(tape, position, markers)
                    }
                }),
                Item::remove_marker(current_marker),
            ])
            .into(),
            Item::custom(move |tape, position, markers| {
                if brk3.load(Ordering::SeqCst) {
                    Item::assert_marker_offset("list end", ListEntry::WIDTH as _, "at list end + one item").run(tape, position, markers)
                } else {
                    Item::assert_marker_offset("list end", 0, "at list end").run(tape, position, markers)
                }
            }),
            Instruction::Left.conv::<Item>().repeat(2 * ListEntry::WIDTH),
            Loop::new(vec![Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
            Item::assert_position(Positions::LIST_HEADSTOP, pass_name),
            offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::LIST_START)),
        ])
        .comment(format!("list pass: {pass_name}"), 180)
    }

    // Not useful for the wider numbers as it relies on the number being single-cell
    fn print_decimal_cell() -> Item {
        // Taken from https://esolangs.org/wiki/Brainfuck_algorithms#Print_value_of_cell_x_as_number_(8-bit)
        // I'm not 100% certain how this works
        Item::parse(
            ">>++++++++++<<[->+>-[>+>>]>[+[-<+>]>+>>]<<<<<<]>>[-]>>>++++++++++<[->-[>+>>]>\
            [+[-<+>]>+>>]<<<<<]>[-]>>[>++++++[-<++++++++>]<.<<+>+>[-]]<[<[->-<]++++++[->++++++++<]>.[-]\
            ]<<++++++[-<++++++++>]<.[-]<<[-<+>]<",
        )
        .expect("should be valid")
    }

    fn pull_back(offset: usize) -> Item {
        Item::Sequence(vec![
            Item::assert_marker_offset("target IP", 0, format!("pull {offset}")),
            offset_to_insns(offset_from(ListEntry::EXIST_FLAG, ListEntry::DATA_START + offset)),
            Loop::new(vec![
                Instruction::Dec.into(),
                offset_to_insns(offset_from(ListEntry::DATA_START + offset, ListEntry::EXIST_FLAG)),
                Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH),
                Loop::new(vec![Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                Item::assert_position(Positions::LIST_HEADSTOP, "return to headstop"),
                offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::FOUND_IP + offset)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(Positions::FOUND_IP + offset, Positions::LIST_START)),
                Loop::new(vec![Instruction::Right.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                Item::assert_marker_offset("target IP", 0, "return to target"),
                offset_to_insns(offset_from(ListEntry::EXIST_FLAG, ListEntry::DATA_START + offset)),
            ])
            .indent()
            .into(),
            offset_to_insns(offset_from(ListEntry::DATA_START + offset, ListEntry::EXIST_FLAG)),
            Item::assert_marker_offset("target IP", 0, format!("pull {offset} finish")),
        ])
    }

    Ok(Item::Sequence(vec![
        Item::assert_position(Positions::PACKET_LOOP_START, "after loop"),
        Item::Comment("begin output".to_owned(), 240),
        offset_to_insns(offset_from(Positions::PACKET_LOOP_START, Positions::SCRATCH_SPACE - 1)),
        Instruction::Inc.conv::<Item>().repeat(5),
        Loop::new(vec![
            Instruction::Dec.into(),
            Instruction::Right.into(),
            Instruction::Dec.conv::<Item>().repeat(2),
            Instruction::Left.into(),
        ])
        .into(),
        Instruction::Right.into(),
        Item::assert_position(Positions::SCRATCH_SPACE, "begin decimal conversion"),
        offset_to_insns(offset_from(Positions::SCRATCH_SPACE, Positions::NO_PACKETS + 1)),
        Instruction::Dec.into(),
        offset_to_insns(offset_from(Positions::NO_PACKETS + 1, Positions::NO_UDP + 1)),
        Instruction::Dec.into(),
        offset_to_insns(offset_from(Positions::NO_UDP + 1, Positions::SCRATCH_SPACE)),
        Loop::new(vec![
            Instruction::Dec.into(),
            Instruction::Right.into(),
            Loop::new(vec![Instruction::Dec.into(), Instruction::Right.into()]).into(),
            Item::assert_position(Positions::TRANSPORT_BYTES + 1, "right moving"),
            offset_to_insns(offset_from(Positions::TRANSPORT_BYTES + 1, Positions::SCRATCH_SPACE)),
        ])
        .into(),
        offset_to_insns(offset_from(Positions::SCRATCH_SPACE, Positions::NO_PACKETS + 1)),
        zero_cell(),
        offset_to_insns(offset_from(Positions::NO_PACKETS + 1, Positions::NO_UDP + 1)),
        zero_cell(),
        offset_to_insns(offset_from(Positions::NO_UDP + 1, Positions::TRANSPORT_BYTES + 1)),
        write_text(Text::TransportLevelData),
        Item::assert_position(Positions::TRANSPORT_BYTES + 1, "after first output"),
        offset_to_insns(offset_from(Positions::TRANSPORT_BYTES + 1, Positions::TRANSPORT_BYTES_START)),
        display_decimal(Positions::TRANSPORT_BYTES_WIDTH, 0),
        write_text(Text::BytesNewline),
        offset_to_insns(offset_from(Positions::TRANSPORT_BYTES_START, Positions::NO_UDP_START)),
        display_decimal(Positions::NO_UDP_WIDTH, 0),
        write_text(Text::UDP),
        offset_to_insns(offset_from(Positions::NO_UDP_START, Positions::NO_PACKETS_START)),
        Item::Sequence(vec![
            drain(&[-4, 4 + Positions::NO_PACKETS_WIDTH as isize], true),
            Instruction::Right.into(),
        ])
        .repeat(Positions::NO_PACKETS_WIDTH),
        offset_to_insns(Positions::NO_PACKETS_WIDTH as isize),
        Item::Sequence(vec![Instruction::Right.into(), Instruction::Inc.into()]).repeat(Positions::NO_PACKETS_WIDTH),
        Loop::new(vec![
            Instruction::Dec.into(),
            offset_to_insns(1 + Positions::NO_PACKETS_WIDTH as isize),
            Loop::new(vec![
                offset_to_insns(-2 + -2 * (Positions::NO_PACKETS_WIDTH as isize)),
                operate::<DecimalSub<{ Positions::NO_PACKETS_WIDTH }>>(8),
                offset_to_insns(2 + 2 * (Positions::NO_PACKETS_WIDTH as isize)),
                Instruction::Dec.into(),
            ])
            .indent()
            .conv::<Item>()
            .comment("subtraction level", 140),
            offset_to_insns(-1 - Positions::NO_PACKETS_WIDTH as isize),
            Instruction::Left.into(),
        ])
        .indent()
        .conv::<Item>()
        .comment("subtract UDP from total packets", 200),
        offset_to_insns(-7),
        Item::assert_position(11, "TCP packets"),
        display_decimal(Positions::NO_PACKETS_WIDTH, 0),
        write_text(Text::TCPNewline),
        Item::assert_position(11, "before clear subtraction"),
        offset_to_insns(14),
        Item::Sequence(vec![Instruction::Right.into(), zero_cell()]).repeat(Positions::NO_PACKETS_WIDTH),
        Item::assert_position(32, "after clear subtraction"),
        // TODO: Write text on line before division
        // Prepare division
        offset_to_insns(offset_from(32, 6)),
        Item::Sequence(vec![Instruction::Right.into(), zero_cell()]).repeat(48 - 7 - 9),
        Item::assert_position(38, "after clear for division"),
        offset_to_insns(offset_from(38, 19)),
        Item::add_marker("divide D"),
        Item::Sequence(vec![zero_cell(), Instruction::Left.into()]).repeat(Positions::NO_PACKETS_WIDTH),
        Item::assert_position(19 - Positions::NO_PACKETS_WIDTH, "after zero 1 for division"),
        offset_to_insns(offset_from(19 - Positions::NO_PACKETS_WIDTH, 0)),
        Item::Sequence(vec![
            drain(&[offset_from(0, 19 - Positions::NO_PACKETS_WIDTH + 1)], true),
            Instruction::Right.into(),
        ])
        .repeat(Positions::NO_PACKETS_WIDTH),
        Item::assert_position(7, "after move divisor for division"),
        offset_to_insns(offset_from(7, 48)),
        Item::Sequence(vec![drain(&[offset_from(47, 11)], true), Instruction::Left.into()]).repeat(Positions::TRANSPORT_BYTES_WIDTH),
        Item::assert_position(48 - Positions::TRANSPORT_BYTES_WIDTH, "after move dividend for division"),
        offset_to_insns(offset_from(48 - Positions::TRANSPORT_BYTES_WIDTH, 11)),
        Item::add_marker("divide N"),
        offset_to_insns(offset_from(11, 0)),
        divide(),
        Item::assert_position(0, "after division"),
        write_text(Text::BytesPerPacket),
        // This isn't efficient - most of the cells are *already* guaranteed to be 0, but at this point
        // I'm not going to spend time figuring out which specific cells need zeroing.
        Item::Sequence(vec![zero_cell(), Instruction::Right.into()]).repeat(Positions::LIST_START),
        Item::assert_position(Positions::LIST_START, "division cleanup done"),
        // TODO: output destination IP stats
        // Reset list items' scratch space, just in case
        // Also, set MARKED_FLAG to 1 for each one
        Loop::new(vec![
            Item::Sequence(vec![Instruction::Right.into(), zero_cell()]).repeat(3),
            offset_to_insns(offset_from(ListEntry::COUNT - 1, ListEntry::MARKED_FLAG)),
            Instruction::Inc.into(),
            offset_to_insns(offset_from(ListEntry::MARKED_FLAG, ListEntry::WIDTH)),
        ])
        .into(),
        Item::add_marker("list end"),
        Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH),
        Loop::new(vec![Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
        Item::assert_position(Positions::LIST_HEADSTOP, "return to headstop"),
        offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::LIST_LOOP_FLAG)),
        Instruction::Inc.into(),
        Loop::new(vec![
            Item::assert_position(Positions::LIST_LOOP_FLAG, "list loop start"),
            offset_to_insns(offset_from(Positions::LIST_LOOP_FLAG, Positions::LIST_START)),
            // Yes, some/most/all of these passes *could* be collapsed into one
            // Given that this is more understandable: no, they will be kept separate
            list_pass("zero check", |_| {
                // Set `scratch1` to `count`==0
                Item::Sequence(vec![
                    offset_to_insns(offset_from(ListEntry::EXIST_FLAG, ListEntry::COUNT)),
                    Instruction::Left.into(),
                    Instruction::Left.into(),
                    Instruction::Inc.into(),
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Loop::new(vec![
                        Instruction::Dec.into(),
                        Instruction::Left.into(),
                        Instruction::Inc.into(),
                        Instruction::Left.into(),
                        zero_cell(),
                        Instruction::Right.into(),
                        Instruction::Right.into(),
                    ])
                    .into(),
                    Instruction::Left.into(),
                    drain(&[1], true),
                    Instruction::Right.into(),
                    offset_to_insns(offset_from(ListEntry::COUNT, ListEntry::WIDTH)),
                ])
            }),
            list_pass("find greater items", |_| {
                Item::Sequence(vec![
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Instruction::Inc.into(),
                    Instruction::Left.into(),
                    Loop::new(vec![
                        zero_cell(),
                        Instruction::Right.into(),
                        Instruction::Dec.into(),
                        Instruction::Left.into(),
                    ])
                    .into(),
                    Instruction::Right.into(),
                    // On scratch1 i.e. 1 iff count!=0 else 0
                    Instruction::Left.into(),
                    Instruction::Left.into(),
                    Instruction::Left.into(),
                    zero_cell(),
                    Instruction::Right.into(),
                    Loop::new(vec![
                        Instruction::Dec.into(),
                        Instruction::Left.into(),
                        Instruction::Inc.into(),
                        Instruction::Right.into(),
                        Instruction::Right.into(),
                        Instruction::Right.into(),
                        Instruction::Inc.into(),
                        Instruction::Left.into(),
                        Instruction::Left.into(),
                    ])
                    .into(),
                    Instruction::Left.into(),
                    Item::assert_marker_offset("current item", 0, "return to exist"),
                    drain(&[1], true),
                    Instruction::Inc.into(),
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Instruction::Dec.into(),
                    Instruction::Dec.into(),
                    // If 0, mark
                    Instruction::Left.into(),
                    Instruction::Inc.into(),
                    Instruction::Right.into(),
                    Loop::new(vec![
                        zero_cell_up(),
                        Instruction::Left.into(),
                        Instruction::Dec.into(),
                        Instruction::Right.into(),
                    ])
                    .into(),
                    offset_to_insns(offset_from(ListEntry::SCRATCH + 1, ListEntry::WIDTH)),
                ])
            }),
            list_pass("check for any greater items", |brk| {
                Item::Sequence(vec![
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Loop::new(vec![
                        drain(&[1], true),
                        Instruction::Left.into(),
                        Instruction::Left.into(),
                        Item::assert_marker_offset("current item", ListEntry::EXIST_FLAG as _, "exist flag"),
                        Loop::new(vec![Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                        Item::custom(move |_, _, _| brk.store(true, Ordering::SeqCst)),
                        Item::assert_position(Positions::LIST_HEADSTOP, "return to headstop"),
                        offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::GREATER_FLAG)),
                        zero_cell(),
                        Instruction::Inc.into(),
                        offset_to_insns(offset_from(Positions::GREATER_FLAG, Positions::LIST_START)),
                        Loop::new(vec![Instruction::Right.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                        Instruction::Right.conv::<Item>().repeat(ListEntry::WIDTH),
                        offset_to_insns(offset_from(ListEntry::WIDTH, 2)),
                    ])
                    .into(),
                    offset_to_insns(offset_from(2, ListEntry::WIDTH)),
                ])
            }),
            list_pass("restore greater markers", |_| {
                Item::Sequence(vec![
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    Instruction::Right.into(),
                    drain(&[-1], true),
                    offset_to_insns(offset_from(3, ListEntry::WIDTH)),
                ])
            }),
            offset_to_insns(offset_from(Positions::LIST_START, Positions::LIST_LOOP_FLAG)),
            zero_cell(),
            offset_to_insns(offset_from(Positions::LIST_LOOP_FLAG, Positions::GREATER_FLAG)),
            // If 1, loop continues
            Loop::new(vec![
                Item::assert_position(Positions::GREATER_FLAG, "if greater exists"),
                zero_cell(),
                offset_to_insns(offset_from(Positions::GREATER_FLAG, Positions::LIST_LOOP_FLAG)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(Positions::LIST_LOOP_FLAG, Positions::GENERAL_COUNT)),
                Instruction::Inc.into(),
                offset_to_insns(offset_from(Positions::GENERAL_COUNT, Positions::LIST_START)),
                list_pass("decrement", |_| {
                    Item::Sequence(vec![
                        offset_to_insns(offset_from(ListEntry::EXIST_FLAG, ListEntry::SCRATCH)),
                        zero_cell(),
                        offset_to_insns(offset_from(ListEntry::SCRATCH, ListEntry::COUNT)),
                        // if zero, clear mark
                        // else, decrement
                        Instruction::Left.into(),
                        Instruction::Inc.into(),
                        Instruction::Right.into(),
                        Loop::new(vec![
                            drain(&[-2], true),
                            Instruction::Left.into(),
                            Instruction::Left.into(),
                            Instruction::Dec.into(),
                            Instruction::Right.into(),
                            Instruction::Dec.into(),
                            Instruction::Right.into(),
                        ])
                        .into(),
                        Instruction::Left.into(),
                        Instruction::Left.into(),
                        drain(&[2], true),
                        Instruction::Right.into(),
                        // [if 1: above if zero]
                        Loop::new(vec![
                            zero_cell(),
                            offset_to_insns(offset_from(ListEntry::COUNT - 1, ListEntry::MARKED_FLAG)),
                            zero_cell(),
                            offset_to_insns(offset_from(ListEntry::MARKED_FLAG, ListEntry::COUNT - 1)),
                        ])
                        .into(),
                        offset_to_insns(offset_from(ListEntry::COUNT - 1, ListEntry::WIDTH)),
                    ])
                }),
                offset_to_insns(offset_from(Positions::LIST_START, Positions::GREATER_FLAG)),
            ])
            .into(),
            Item::assert_position(Positions::GREATER_FLAG, "after loop check"),
            offset_to_insns(offset_from(Positions::GREATER_FLAG, Positions::LIST_LOOP_FLAG)),
        ])
        .indent()
        .into(),
        Item::assert_position(Positions::LIST_LOOP_FLAG, "after loop"),
        offset_to_insns(offset_from(Positions::LIST_LOOP_FLAG, Positions::LIST_START)),
        // At this point, entries are flagged iff they are maximal-count
        // `Positions::GENERAL_COUNT` contains the maximum count
        list_pass("copy out first maximal IP", |brk| {
            Item::Sequence(vec![
                Instruction::Right.into(),
                Loop::new(vec![
                    Instruction::Left.into(),
                    Item::assert_marker_offset("current item", ListEntry::EXIST_FLAG as _, "exist flag"),
                    Item::add_marker("target IP"),
                    zero_cell(),
                    Item::custom(move |_, _, _| brk.store(true, Ordering::SeqCst)),
                    pull_back(0),
                    pull_back(1),
                    pull_back(2),
                    pull_back(3),
                    Instruction::Inc.into(),
                    Item::remove_marker("target IP"),
                    Loop::new(vec![Instruction::Right.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                    Instruction::Right.conv::<Item>().repeat(ListEntry::WIDTH),
                    offset_to_insns(offset_from(ListEntry::WIDTH, 1)),
                ])
                .into(),
                offset_to_insns(offset_from(1, ListEntry::WIDTH)),
            ])
        }),
        list_pass("count targets", |_| {
            Item::Sequence(vec![
                Instruction::Right.into(),
                Loop::new(vec![
                    zero_cell(),
                    Instruction::Left.into(),
                    Item::assert_marker_offset("current item", ListEntry::EXIST_FLAG as _, "exist flag"),
                    Item::add_marker("current target"),
                    zero_cell(),
                    Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH),
                    Loop::new(vec![Instruction::Left.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                    Item::assert_position(Positions::LIST_HEADSTOP, "return to headstop"),
                    offset_to_insns(offset_from(Positions::LIST_HEADSTOP, Positions::TARGET_COUNT)),
                    Instruction::Inc.into(),
                    offset_to_insns(offset_from(Positions::TARGET_COUNT, Positions::LIST_START)),
                    Loop::new(vec![Instruction::Right.conv::<Item>().repeat(ListEntry::WIDTH)]).into(),
                    Item::assert_marker_offset("current target", 0, "return to target"),
                    Instruction::Inc.into(),
                    Item::remove_marker("current target"),
                    Instruction::Right.into(),
                ])
                .into(),
                offset_to_insns(offset_from(1, ListEntry::WIDTH)),
            ])
        }),
        // At this point, all information that we need *should* have been pulled from the list
        // Clear the first entry as we (may?) need the space
        Item::Sequence(vec![zero_cell(), Instruction::Right.into()]).repeat(ListEntry::WIDTH),
        offset_to_insns(offset_from(Positions::LIST_START + ListEntry::WIDTH, Positions::TEXT_SPACE)),
        write_text(Text::MostPopular),
        offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::TARGET_COUNT - 1)),
        /*
        Format:
           c=1  Most popular destination was IP with N packet[s]
           c>1  Most popular destinations were IP and M other[s] with N packet[s] each
         */
        Instruction::Inc.into(),
        Instruction::Right.into(),
        // TEMP: pretend there are more destinations
        Instruction::Inc.into(),
        Instruction::Inc.into(),
        Instruction::Inc.into(),
        //
        Instruction::Dec.into(),
        // If nonzero, `cell` extra destinations
        Loop::new(vec![
            offset_to_insns(offset_from(Positions::TARGET_COUNT, Positions::TEXT_SPACE)),
            write_text(Text::DestinationsWere),
            offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::TARGET_COUNT)),
            drain(&[-2], true),
            Instruction::Left.into(),
            Instruction::Dec.into(),
            Instruction::Right.into(),
        ])
        .into(),
        Instruction::Left.into(),
        Loop::new(vec![
            zero_cell(),
            offset_to_insns(offset_from(Positions::TARGET_COUNT - 1, Positions::TEXT_SPACE)),
            write_text(Text::DestinationWas),
            offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::TARGET_COUNT - 1)),
        ])
        .into(),
        offset_to_insns(offset_from(Positions::TARGET_COUNT - 1, Positions::FOUND_IP - 8)),
        Instruction::Left.into(),
        Item::Sequence(vec![Instruction::Right.into(), Instruction::Inc.conv::<Item>().repeat(2)]).repeat(4),
        Instruction::Dec.into(),
        Instruction::Left.conv::<Item>().repeat(9),
        // set cell to b'.'
        Item::parse("+++++++[>+++++++<-]>---").expect("should be valid"),
        drain(&[1, 1, 1, 1], true),
        offset_to_insns(5),
        Loop::new(vec![
            Instruction::Dec.into(),
            offset_to_insns(8),
            drain(&[6], true),
            offset_to_insns(6),
            print_decimal_cell(),
            zero_cell(),
            offset_to_insns(-(6 + 8)),
            // print b'.' if required
            Loop::new(vec![
                zero_cell(),
                offset_to_insns(-4),
                Instruction::Output.into(),
                offset_to_insns(4),
            ])
            .into(),
            Instruction::Right.into(),
        ])
        .indent()
        .into(),
        Item::assert_position(Positions::TARGET_COUNT - 2 - 1, "after IP output"), // -2 because it was `drain`ed to the left
        offset_to_insns(-5),
        Loop::new(vec![zero_cell(), Instruction::Left.into()]).into(),
        Item::assert_position(Positions::TARGET_COUNT - 2 - 10, "after IP cleanup"),
        offset_to_insns(offset_from(Positions::TARGET_COUNT - 2 - 10, Positions::TARGET_COUNT - 2)),
        // If nonzero, `cell` extra destinations
        Instruction::Left.into(),
        Instruction::Left.into(),
        Item::parse("+++++++++++[>++++++++++<-]>+++++").expect("should be valid"),
        Instruction::Right.into(),
        Loop::new(vec![
            offset_to_insns(offset_from(Positions::TARGET_COUNT - 2, Positions::TEXT_SPACE)),
            write_text(Text::And),
            offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::TARGET_COUNT - 2)),
            print_decimal_cell(),
            offset_to_insns(offset_from(Positions::TARGET_COUNT - 2, Positions::TEXT_SPACE)),
            write_text(Text::Other),
            // Leave a marker of multiple IPs for later
            Instruction::Left.into(),
            Instruction::Inc.into(),
            Instruction::Right.into(),
            offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::TARGET_COUNT - 2)),
            Instruction::Dec.into(),
            Loop::new(vec![
                zero_cell(),
                Instruction::Left.into(),
                Instruction::Output.into(),
                Instruction::Right.into(),
            ])
            .into(),
        ])
        .into(),
        offset_to_insns(offset_from(Positions::TARGET_COUNT - 2, Positions::TEXT_SPACE)),
        write_text(Text::With),
        offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::GENERAL_COUNT)),
        print_decimal_cell(),
        offset_to_insns(offset_from(Positions::GENERAL_COUNT, Positions::TEXT_SPACE)),
        write_text(Text::Packet),
        offset_to_insns(offset_from(Positions::TEXT_SPACE, Positions::GENERAL_COUNT)),
        Instruction::Dec.into(),
        Loop::new(vec![
            zero_cell(),
            offset_to_insns(-9),
            Instruction::Output.into(),
            offset_to_insns(9),
        ])
        .into(),
        offset_to_insns(offset_from(Positions::GENERAL_COUNT, Positions::TEXT_SPACE - 1)),
        Loop::new(vec![zero_cell(), write_text(Text::Each)]).into(),
        write_text(Text::Newline),
    ]))
}

fn main() -> anyhow::Result<()> {
    let program = vec![
        discard_header(),
        setup_state(),
        Item::assert_position(Positions::PACKET_LOOP_START, "start"),
        read_packet_loop(),
        output()?,
    ];

    let program = Program::build(program.clone().build())?;
    println!("{}", program.as_text());
    let data = fs_err::read("test.pcap")?;
    let input = Cursor::new(data[..1781].to_owned()); // Header + first 13 packets

    let mut interpreter = Interpreter::new(program, input);
    interpreter.set_print_level(160);
    interpreter.run()?;
    // println!("\n\n===\n");
    println!("{}", interpreter.tape());

    Ok(())
}
