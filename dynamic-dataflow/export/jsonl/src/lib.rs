use dataflow_core::delta::Delta;
use dataflow_core::export::*;
use dataflow_core::operation::OperationKind;
use dataflow_core::space::SpaceKind;
use dataflow_core::value::PartialValue;
use dataflow_core::{Index, Tick};

use serde::Serialize;
use std::fmt::{self, Write};
use std::fs::File;
use std::io::BufWriter;
use std::io::Write as _;
use std::path::Path;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};

pub struct JsonlExporter {
    threads: Vec<JoinHandle<()>>,
    tick_writer: Sender<TickMessage>,
    delta_writer: Sender<DeltaMessage>,
    addr_dep_writer: Sender<AddrDepMessage>,
    value_dep_writer: Sender<ValueDepMessage>,
    const_dep_writer: Sender<ConstDepMessage>,
    cf_dep_writer: Sender<CfDepMessage>,
}

impl JsonlExporter {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        let root = root.as_ref();
        let _ = std::fs::create_dir_all(root);

        let mut threads = Vec::with_capacity(6);

        let (tick_writer, chan) = mpsc::channel();
        let out = BufWriter::new(File::create(root.join("ticks.jsonl")).unwrap());
        threads.push(thread::spawn(move || write_ticks(chan, out)));

        let (delta_writer, chan) = mpsc::channel();
        let out = BufWriter::new(File::create(root.join("deltas.jsonl")).unwrap());
        threads.push(thread::spawn(move || write_deltas(chan, out)));

        let (addr_dep_writer, chan) = mpsc::channel();
        let out = BufWriter::new(File::create(root.join("addr_deps.jsonl")).unwrap());
        threads.push(thread::spawn(move || write_addr_deps(chan, out)));

        let (value_dep_writer, chan) = mpsc::channel();
        let out = BufWriter::new(File::create(root.join("input_deps.jsonl")).unwrap());
        threads.push(thread::spawn(move || write_value_deps(chan, out)));

        let (const_dep_writer, chan) = mpsc::channel();
        let const_out = BufWriter::new(File::create(root.join("const_uses.jsonl")).unwrap());
        let value_out = BufWriter::new(File::create(root.join("const_input_deps.jsonl")).unwrap());
        let addr_out = BufWriter::new(File::create(root.join("const_addr_deps.jsonl")).unwrap());
        threads.push(thread::spawn(move || {
            write_const_deps(chan, const_out, value_out, addr_out)
        }));

        let (cf_dep_writer, chan) = mpsc::channel();
        let out = BufWriter::new(File::create(root.join("cf_deps.jsonl")).unwrap());
        threads.push(thread::spawn(move || write_cf_deps(chan, out)));

        Self {
            threads,
            tick_writer,
            delta_writer,
            addr_dep_writer,
            value_dep_writer,
            const_dep_writer,
            cf_dep_writer,
        }
    }
}

impl DataflowExport for JsonlExporter {
    fn write(&mut self, msg: Message) -> Result<(), ExportError> {
        match msg {
            Message::Tick(tick, offset, disasm) => {
                self.tick_writer
                    .send(TickMessage::Tick(tick, offset, String::from(disasm)))
                    .unwrap();
            }
            Message::Deltas(start, deltas) => {
                let deltas = deltas
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(index, (tick, opcode, delta))| (index + start, tick, opcode, delta))
                    .collect();
                self.delta_writer
                    .send(DeltaMessage::Deltas(deltas))
                    .unwrap();
            }
            Message::AddrDeps(deps) => {
                self.addr_dep_writer
                    .send(AddrDepMessage::AddrDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ValueDeps(deps) => {
                self.value_dep_writer
                    .send(ValueDepMessage::ValueDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ConstAddrDeps(deps) => {
                self.const_dep_writer
                    .send(ConstDepMessage::AddrDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ConstValueDeps(deps) => {
                self.const_dep_writer
                    .send(ConstDepMessage::ValueDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ControlflowDeps(deps) => {
                self.cf_dep_writer
                    .send(CfDepMessage::CfDeps(Vec::from(deps)))
                    .unwrap();
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ExportError> {
        Ok(())
    }
}

impl Drop for JsonlExporter {
    fn drop(&mut self) {
        let _ = self.tick_writer.send(TickMessage::Done);
        let _ = self.delta_writer.send(DeltaMessage::Done);
        let _ = self.addr_dep_writer.send(AddrDepMessage::Done);
        let _ = self.value_dep_writer.send(ValueDepMessage::Done);
        let _ = self.const_dep_writer.send(ConstDepMessage::Done);
        let _ = self.cf_dep_writer.send(CfDepMessage::Done);

        for thread in self.threads.drain(..) {
            thread.join().unwrap();
        }
    }
}

enum TickMessage {
    Tick(Tick, u64, String),
    Done,
}

fn write_ticks(chan: Receiver<TickMessage>, mut out: BufWriter<File>) {
    #[derive(Serialize)]
    struct TickRecord<'a> {
        #[serde(rename = "_key")]
        key: &'a str,
        runid: u64,
        tick: usize,
        pc: u64,
        disas: String,
    }

    let mut key_buffer = String::new();

    while let Ok(msg) = chan.recv() {
        match msg {
            TickMessage::Tick(tick, pc, disas) => {
                write!(key_buffer, "{}", tick).unwrap();

                let record = TickRecord {
                    key: key_buffer.as_str(),
                    runid: 0,
                    tick: tick as usize,
                    pc: pc,
                    disas,
                };
                let _ = serde_json::to_writer(&mut out, &record);
                let _ = write!(&mut out, "\n");
                key_buffer.clear();
            }
            TickMessage::Done => {
                break;
            }
        }
    }

    out.flush().unwrap();
}

enum DeltaMessage {
    Deltas(Vec<(Index, Tick, OperationKind, Delta)>),
    Done,
}

fn write_deltas(chan: Receiver<DeltaMessage>, mut out: BufWriter<File>) {
    use tracing::warn;

    let _span = tracing::trace_span!("write_deltas").entered();

    #[derive(Serialize)]
    struct DeltaRecord<'a> {
        #[serde(rename = "_key")]
        key: &'a str,
        runid: u64,
        index: usize,
        tick: u64,
        opcode: usize,
        bank: Option<usize>,
        addr: Option<u64>,
        val: Option<u64>,
        raw: Option<&'a str>,
        size: Option<u64>,
        assocd_bank: Option<usize>,
        assocd_addr: Option<u64>,
        assocd_size: Option<u64>,
    }

    let mut key_buffer = String::new();
    let mut raw_buffer = String::new();

    while let Ok(msg) = chan.recv() {
        match msg {
            DeltaMessage::Deltas(mut deltas) => {
                for (index, tick, opc, delta) in deltas.drain(..) {
                    write!(key_buffer, "{}", index).unwrap();

                    let mut record = DeltaRecord {
                        key: key_buffer.as_str(),
                        runid: 0,
                        index,
                        tick: tick,
                        opcode: opc as usize,
                        bank: None,
                        addr: None,
                        val: None,
                        raw: None,
                        size: None,
                        assocd_bank: None,
                        assocd_addr: None,
                        assocd_size: None,
                    };

                    if delta.space.kind() != SpaceKind::Other {
                        record.bank = Some(delta.space.kind() as usize);
                        record.addr = Some(delta.offset);
                        record.val = match delta.size {
                            0 => None,
                            1 => delta.value.as_u8().map(|v| v as u64),
                            2 => delta.value.as_u16().map(|v| v as u64),
                            4 => delta.value.as_u32().map(|v| v as u64),
                            8 => delta.value.as_u64(),
                            /*16 => delta.value.as_u64(),*/
                            _ => {
                                warn!(
                                    tick = tick,
                                    size = delta.size,
                                    "unable to cast value to concrete value"
                                );
                                None
                            }
                        };
                        let raw = &delta.value.as_raw()[..delta.size as usize];
                        write!(raw_buffer, "{}", PartialPrinter(raw)).unwrap();
                        record.raw = Some(raw_buffer.as_str());
                        record.size = Some(delta.size);
                    }

                    if let Some(range) = Delta::associated_range(&delta) {
                        record.assocd_bank = Some(range.space().kind() as usize);
                        record.assocd_addr = Some(range.offset());
                        record.assocd_size = Some(range.size());
                    }

                    let _ = serde_json::to_writer(&mut out, &record);
                    let _ = write!(&mut out, "\n");
                    raw_buffer.clear();
                    key_buffer.clear();
                }
            }
            DeltaMessage::Done => {
                tracing::trace!("received done message");
                break;
            }
        }
    }

    out.flush().unwrap();
}

enum AddrDepMessage {
    AddrDeps(Vec<Edge>),
    Done,
}

fn write_addr_deps(chan: Receiver<AddrDepMessage>, mut out: BufWriter<File>) {
    #[derive(Serialize)]
    struct DepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        maybe: u8,
    }

    let key_prefix = "operationruns/";
    let mut from_buffer = String::new();
    let mut to_buffer = String::new();

    while let Ok(msg) = chan.recv() {
        match msg {
            AddrDepMessage::AddrDeps(mut deps) => {
                for dep in deps.drain(..) {
                    let (from, to, maybe) = match dep {
                        Edge::Certain(from, to) => (from, to, 0),
                        Edge::Maybe(from, to) => (from, to, 1),
                    };
                    write!(from_buffer, "{}{}", key_prefix, from).unwrap();
                    write!(to_buffer, "{}{}", key_prefix, to).unwrap();
                    let record = DepRecord {
                        from: from_buffer.as_str(),
                        to: to_buffer.as_str(),
                        maybe,
                    };
                    let _ = serde_json::to_writer(&mut out, &record);
                    let _ = write!(&mut out, "\n");
                    from_buffer.clear();
                    to_buffer.clear();
                }
            }
            AddrDepMessage::Done => {
                break;
            }
        }
    }

    out.flush().unwrap();
}

enum ValueDepMessage {
    ValueDeps(Vec<(Edge, u8)>),
    Done,
}

fn write_value_deps(chan: Receiver<ValueDepMessage>, mut out: BufWriter<File>) {
    #[derive(Serialize)]
    struct DepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        pos: u8,
        maybe: u8,
    }

    let key_prefix = "operationruns/";
    let mut from_buffer = String::new();
    let mut to_buffer = String::new();

    while let Ok(msg) = chan.recv() {
        match msg {
            ValueDepMessage::ValueDeps(mut deps) => {
                for (dep, pos) in deps.drain(..) {
                    let (from, to, maybe) = match dep {
                        Edge::Certain(from, to) => (from, to, 0),
                        Edge::Maybe(from, to) => (from, to, 1),
                    };
                    write!(from_buffer, "{}{}", key_prefix, from).unwrap();
                    write!(to_buffer, "{}{}", key_prefix, to).unwrap();
                    let record = DepRecord {
                        from: from_buffer.as_str(),
                        to: to_buffer.as_str(),
                        pos,
                        maybe,
                    };
                    let _ = serde_json::to_writer(&mut out, &record);
                    let _ = write!(&mut out, "\n");
                    from_buffer.clear();
                    to_buffer.clear();
                }
            }
            ValueDepMessage::Done => {
                break;
            }
        }
    }

    out.flush().unwrap();
}

enum CfDepMessage {
    CfDeps(Vec<Edge>),
    Done,
}

fn write_cf_deps(chan: Receiver<CfDepMessage>, mut out: BufWriter<File>) {
    #[derive(Serialize)]
    struct DepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        maybe: u8,
    }

    let key_prefix = "operationruns/";
    let mut from_buffer = String::new();
    let mut to_buffer = String::new();

    while let Ok(msg) = chan.recv() {
        match msg {
            CfDepMessage::CfDeps(mut deps) => {
                for dep in deps.drain(..) {
                    let (from, to, maybe) = match dep {
                        Edge::Certain(from, to) => (from, to, 0),
                        Edge::Maybe(from, to) => (from, to, 1),
                    };
                    write!(from_buffer, "{}{}", key_prefix, from).unwrap();
                    write!(to_buffer, "{}{}", key_prefix, to).unwrap();
                    let record = DepRecord {
                        from: from_buffer.as_str(),
                        to: to_buffer.as_str(),
                        maybe,
                    };
                    let _ = serde_json::to_writer(&mut out, &record);
                    let _ = write!(&mut out, "\n");
                    from_buffer.clear();
                    to_buffer.clear();
                }
            }
            CfDepMessage::Done => {
                break;
            }
        }
    }

    out.flush().unwrap();
}

enum ConstDepMessage {
    ValueDeps(Vec<(ConstEdge, u8)>),
    AddrDeps(Vec<ConstEdge>),
    Done,
}

fn write_const_deps(
    chan: Receiver<ConstDepMessage>,
    mut const_out: BufWriter<File>,
    mut value_out: BufWriter<File>,
    mut addr_out: BufWriter<File>,
) {
    use tracing::warn;
    let _span = tracing::trace_span!("write_const_deps").entered();

    #[derive(Serialize)]
    struct ConstRecord<'a> {
        #[serde(rename = "_key")]
        key: &'a str,
        val: Option<u64>,
        raw: Option<&'a str>,
        size: usize,
    }

    #[derive(Serialize)]
    struct ValueDepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        pos: u8,
    }

    #[derive(Serialize)]
    struct AddrDepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
    }

    let from_prefix = "operationruns/";
    let to_prefix = "constantuses/";
    let mut key_buffer = String::new();
    let mut from_buffer = String::new();
    let mut to_buffer = String::new();
    let mut raw_buffer = String::new();

    let mut counter: u64 = 0;

    while let Ok(msg) = chan.recv() {
        match msg {
            ConstDepMessage::ValueDeps(mut deps) => {
                for (ConstEdge(index, value), pos) in deps.drain(..) {
                    let size = value.size();
                    let partial = PartialValue::from(value);
                    write!(key_buffer, "{}", counter).unwrap();
                    write!(from_buffer, "{}{}", from_prefix, index).unwrap();
                    write!(to_buffer, "{}{}", to_prefix, counter).unwrap();
                    let mut record = ConstRecord {
                        key: key_buffer.as_str(),
                        val: None,
                        raw: None,
                        size,
                    };
                    record.val = match size {
                        0 => None,
                        1 => partial.as_u8().map(|v| v as u64),
                        2 => partial.as_u16().map(|v| v as u64),
                        4 => partial.as_u32().map(|v| v as u64),
                        8 => partial.as_u64(),
                        16 => partial.as_u64(),
                        _ => {
                            warn!(size = size, "unable to cast value to concrete value");
                            None
                        }
                    };
                    let raw = &partial.as_raw()[..size];
                    write!(raw_buffer, "{}", PartialPrinter(raw)).unwrap();
                    record.raw = Some(raw_buffer.as_str());
                    let _ = serde_json::to_writer(&mut const_out, &record);
                    let _ = write!(&mut const_out, "\n");

                    let record = ValueDepRecord {
                        from: from_buffer.as_str(),
                        to: to_buffer.as_str(),
                        pos,
                    };
                    let _ = serde_json::to_writer(&mut value_out, &record);
                    let _ = write!(&mut value_out, "\n");

                    key_buffer.clear();
                    from_buffer.clear();
                    to_buffer.clear();
                    raw_buffer.clear();

                    counter += 1;
                }
            }
            ConstDepMessage::AddrDeps(mut deps) => {
                for ConstEdge(index, value) in deps.drain(..) {
                    let size = value.size();
                    let partial = PartialValue::from(value);
                    write!(key_buffer, "{}", counter).unwrap();
                    write!(from_buffer, "{}{}", from_prefix, index).unwrap();
                    write!(to_buffer, "{}{}", to_prefix, counter).unwrap();
                    let mut record = ConstRecord {
                        key: key_buffer.as_str(),
                        val: None,
                        raw: None,
                        size,
                    };
                    record.val = match size {
                        0 => None,
                        1 => partial.as_u8().map(|v| v as u64),
                        2 => partial.as_u16().map(|v| v as u64),
                        4 => partial.as_u32().map(|v| v as u64),
                        8 => partial.as_u64(),
                        16 => partial.as_u64(),
                        _ => {
                            warn!(size = size, "unable to cast value to concrete value");
                            None
                        }
                    };
                    let raw = &partial.as_raw()[..size];
                    write!(raw_buffer, "{}", PartialPrinter(raw)).unwrap();
                    record.raw = Some(raw_buffer.as_str());
                    let _ = serde_json::to_writer(&mut const_out, &record);
                    let _ = write!(&mut const_out, "\n");

                    let record = AddrDepRecord {
                        from: from_buffer.as_str(),
                        to: to_buffer.as_str(),
                    };
                    let _ = serde_json::to_writer(&mut addr_out, &record);
                    let _ = write!(&mut addr_out, "\n");

                    key_buffer.clear();
                    from_buffer.clear();
                    to_buffer.clear();
                    raw_buffer.clear();

                    counter += 1;
                }
            }
            ConstDepMessage::Done => {
                break;
            }
        }
    }
    const_out.flush().unwrap();
    value_out.flush().unwrap();
    addr_out.flush().unwrap();
}

struct PartialPrinter<'a>(&'a [Option<u8>]);

impl fmt::Display for PartialPrinter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter().rev() {
            match byte {
                Some(b) => write!(f, "{:02x}", b)?,
                None => write!(f, "??")?,
            }
        }
        Ok(())
    }
}
