use dataflow_core::delta::Delta;
use dataflow_core::export::*;
use dataflow_core::operation::OperationKind;
use dataflow_core::space::SpaceKind;
use dataflow_core::value::PartialValue;
use dataflow_core::{Index, Tick};

use serde::Serialize;
use std::fmt::Write as _;
use std::io::Write as _;
use std::thread::{self, JoinHandle};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

// TODO:
// - Add options for configurable endpoint + auth
// - Investigate Velocy(Stream/Pack)
// - Performance measurements + tuning
// - Logging
// - Error handling
// - Options for clearing/initializing database

const HIGH_WATERMARK: usize = 0x3f0000;
const OVERHEAD: usize = 0x10000;
const ENDPOINT: &'static str = "http://127.0.0.1:8529/_db/dataflowdb/_api/import";

pub struct ArangoExporter {
    thread: Option<JoinHandle<()>>,
    sender: UnboundedSender<InternalMessage>,
}

impl ArangoExporter {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let thread = Some(thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();

            rt.block_on(async move { export_thread(receiver).await.unwrap() });
        }));
        Self { thread, sender }
    }
}

impl DataflowExport for ArangoExporter {
    fn write(&mut self, msg: Message) -> Result<(), ExportError> {
        match msg {
            Message::Tick(tick, offset, disasm) => {
                self.sender
                    .send(InternalMessage::Tick(tick, offset, String::from(disasm)))
                    .unwrap();
            }
            Message::Deltas(start, deltas) => {
                let deltas = deltas
                    .iter()
                    .copied()
                    .enumerate()
                    .map(|(index, (tick, opcode, delta))| (index + start, tick, opcode, delta))
                    .collect();
                self.sender.send(InternalMessage::Deltas(deltas)).unwrap();
            }
            Message::AddrDeps(deps) => {
                self.sender
                    .send(InternalMessage::AddrDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ValueDeps(deps) => {
                self.sender
                    .send(InternalMessage::ValueDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ConstAddrDeps(deps) => {
                self.sender
                    .send(InternalMessage::ConstAddrDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ConstValueDeps(deps) => {
                self.sender
                    .send(InternalMessage::ConstValueDeps(Vec::from(deps)))
                    .unwrap();
            }
            Message::ControlflowDeps(deps) => {
                self.sender
                    .send(InternalMessage::CfDeps(Vec::from(deps)))
                    .unwrap();
            }
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ExportError> {
        Ok(())
    }
}

impl Drop for ArangoExporter {
    fn drop(&mut self) {
        let _ = self.sender.send(InternalMessage::Done);
        self.thread.take().map(|handle| handle.join().unwrap());
    }
}

async fn export_thread(
    mut rx: UnboundedReceiver<InternalMessage>,
) -> std::result::Result<(), InternalError> {
    let client = reqwest::Client::new();
    let mut ticks: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut deltas: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut const_uses: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut addr_deps: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut value_deps: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut const_addr_deps: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut const_value_deps: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut cf_deps: Vec<u8> = Vec::with_capacity(HIGH_WATERMARK + OVERHEAD);
    let mut key = String::new();
    let mut const_counter = 0;

    let mut tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();

    while let Some(msg) = rx.recv().await {
        match msg {
            InternalMessage::Tick(tick, offset, disas) => {
                key.clear();
                let _ = write!(key, "{}", tick);
                let record = TickRecord {
                    key: key.as_str(),
                    runid: 0,
                    tick: tick as usize,
                    pc: offset,
                    disas: disas.as_str(),
                };
                let _ = serde_json::to_writer(&mut ticks, &record);
                if ticks.len() >= HIGH_WATERMARK {
                    let ticks = std::mem::replace(
                        &mut ticks,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(client, ticks, "instructionruns", "", "").await;
                    }));
                } else {
                    let _ = write!(ticks, "\n");
                };
            }

            InternalMessage::Deltas(mut d) => {
                for (index, tick, opc, delta) in d.drain(..) {
                    key.clear();
                    let _ = write!(key, "{}", index);
                    let keylen = key.len();

                    let mut bank = None;
                    let mut addr = None;
                    let mut val = None;
                    let mut raw = None;
                    let mut size = None;
                    let mut assocd_bank = None;
                    let mut assocd_addr = None;
                    let mut assocd_size = None;

                    if delta.space.kind() != SpaceKind::Other {
                        bank = Some(delta.space.kind() as usize);
                        addr = Some(delta.offset);
                        val = match delta.size {
                            0 => None,
                            1 => delta.value.as_u8().map(|v| v as u64),
                            2 => delta.value.as_u16().map(|v| v as u64),
                            4 => delta.value.as_u32().map(|v| v as u64),
                            8 => delta.value.as_u64(),
                            /*16 => delta.value.as_u64(),*/
                            _ => {
                                tracing::warn!(
                                    size = delta.size,
                                    tick = tick,
                                    "unable to cast value to concrete value"
                                );
                                None
                            }
                        };
                        let rawval = &delta.value.as_raw()[..delta.size as usize];
                        let _ = write!(key, "{}", PartialPrinter(rawval));
                        raw = Some(&key[keylen..]);
                        size = Some(delta.size);
                    }

                    if let Some(range) = Delta::associated_range(&delta) {
                        assocd_bank = Some(range.space().kind() as usize);
                        assocd_addr = Some(range.offset());
                        assocd_size = Some(range.size());
                    }

                    let record = DeltaRecord {
                        key: &key[..keylen],
                        runid: 0,
                        index,
                        tick,
                        opcode: opc as usize,
                        bank,
                        addr,
                        val,
                        raw,
                        size,
                        assocd_bank,
                        assocd_addr,
                        assocd_size,
                    };

                    let _ = serde_json::to_writer(&mut deltas, &record);
                    let _ = write!(&mut deltas, "\n");
                }
                if deltas.len() >= HIGH_WATERMARK {
                    let deltas = std::mem::replace(
                        &mut deltas,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(client, deltas, "operationruns", "", "").await;
                    }));
                }
            }

            InternalMessage::AddrDeps(mut deps) => {
                for dep in deps.drain(..) {
                    key.clear();
                    let (from, to, maybe) = match dep {
                        Edge::Certain(from, to) => (from, to, 0),
                        Edge::Maybe(from, to) => (from, to, 1),
                    };
                    let _ = write!(key, "{}", from);
                    let to_start = key.len();
                    let _ = write!(key, "{}", to);
                    let record = DepRecord {
                        from: &key[..to_start],
                        to: &key[to_start..],
                        maybe: Some(maybe),
                        pos: None,
                    };
                    let _ = serde_json::to_writer(&mut addr_deps, &record);
                    let _ = write!(&mut addr_deps, "\n");
                }
                if addr_deps.len() >= HIGH_WATERMARK {
                    let addr_deps = std::mem::replace(
                        &mut addr_deps,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(
                            client,
                            addr_deps,
                            "addrdep",
                            "operationruns",
                            "operationruns",
                        )
                        .await;
                    }));
                }
            }

            InternalMessage::ValueDeps(mut deps) => {
                for (dep, pos) in deps.drain(..) {
                    key.clear();
                    let (from, to, maybe) = match dep {
                        Edge::Certain(from, to) => (from, to, 0),
                        Edge::Maybe(from, to) => (from, to, 1),
                    };
                    let _ = write!(key, "{}", from);
                    let to_start = key.len();
                    let _ = write!(key, "{}", to);
                    let record = DepRecord {
                        from: &key[..to_start],
                        to: &key[to_start..],
                        maybe: Some(maybe),
                        pos: Some(pos),
                    };
                    let _ = serde_json::to_writer(&mut value_deps, &record);
                    let _ = write!(&mut value_deps, "\n");
                }
                if value_deps.len() >= HIGH_WATERMARK {
                    let value_deps = std::mem::replace(
                        &mut value_deps,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(
                            client,
                            value_deps,
                            "inputdep",
                            "operationruns",
                            "operationruns",
                        )
                        .await;
                    }));
                }
            }

            InternalMessage::ConstValueDeps(mut deps) => {
                for (ConstEdge(index, value), pos) in deps.drain(..) {
                    let size = value.size();
                    let partial = PartialValue::from(value);

                    key.clear();
                    let _ = write!(key, "{}", const_counter);
                    let from_start = key.len();
                    let _ = write!(key, "{}", index);
                    let raw_start = key.len();
                    let val = match size {
                        0 => None,
                        1 => partial.as_u8().map(|v| v as u64),
                        2 => partial.as_u16().map(|v| v as u64),
                        4 => partial.as_u32().map(|v| v as u64),
                        8 => partial.as_u64(),
                        16 => partial.as_u64(),
                        _ => {
                            tracing::warn!(size = size, "unable to cast value to concrete value");
                            None
                        }
                    };
                    let rawval = &partial.as_raw()[..size];
                    let _ = write!(key, "{}", PartialPrinter(rawval));
                    let record = ConstRecord {
                        key: &key[..from_start],
                        val,
                        raw: Some(&key[raw_start..]),
                        size,
                    };
                    let _ = serde_json::to_writer(&mut const_uses, &record);
                    let _ = write!(const_uses, "\n");

                    let record = DepRecord {
                        from: &key[from_start..],
                        to: &key[..from_start],
                        maybe: None,
                        pos: Some(pos),
                    };
                    let _ = serde_json::to_writer(&mut const_value_deps, &record);
                    let _ = write!(&mut const_value_deps, "\n");
                    const_counter += 1;
                }
                if const_value_deps.len() >= HIGH_WATERMARK {
                    let const_value_deps = std::mem::replace(
                        &mut const_value_deps,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(
                            client,
                            const_value_deps,
                            "constinputdep",
                            "operationruns",
                            "constantuses",
                        )
                        .await;
                    }));
                }
                if const_uses.len() >= HIGH_WATERMARK {
                    let const_uses = std::mem::replace(
                        &mut const_uses,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(client, const_uses, "constantuses", "", "").await;
                    }));
                }
            }

            InternalMessage::ConstAddrDeps(mut deps) => {
                for ConstEdge(index, value) in deps.drain(..) {
                    let size = value.size();
                    let partial = PartialValue::from(value);

                    key.clear();
                    let _ = write!(key, "{}", const_counter);
                    let from_start = key.len();
                    let _ = write!(key, "{}", index);
                    let raw_start = key.len();
                    let val = match size {
                        0 => None,
                        1 => partial.as_u8().map(|v| v as u64),
                        2 => partial.as_u16().map(|v| v as u64),
                        4 => partial.as_u32().map(|v| v as u64),
                        8 => partial.as_u64(),
                        16 => partial.as_u64(),
                        _ => {
                            tracing::warn!(
                                size = size,
                                "unable to cast value of to concrete value"
                            );
                            None
                        }
                    };
                    let rawval = &partial.as_raw()[..size];
                    let _ = write!(key, "{}", PartialPrinter(rawval));
                    let record = ConstRecord {
                        key: &key[..from_start],
                        val,
                        raw: Some(&key[raw_start..]),
                        size,
                    };
                    let _ = serde_json::to_writer(&mut const_uses, &record);
                    let _ = write!(const_uses, "\n");

                    let record = DepRecord {
                        from: &key[from_start..],
                        to: &key[..from_start],
                        maybe: None,
                        pos: None,
                    };
                    let _ = serde_json::to_writer(&mut const_addr_deps, &record);
                    let _ = write!(&mut const_addr_deps, "\n");
                    const_counter += 1;
                }
                if const_addr_deps.len() >= HIGH_WATERMARK {
                    let const_addr_deps = std::mem::replace(
                        &mut const_addr_deps,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(
                            client,
                            const_addr_deps,
                            "constinputdep",
                            "operationruns",
                            "constantuses",
                        )
                        .await;
                    }));
                }
                if const_uses.len() >= HIGH_WATERMARK {
                    let const_uses = std::mem::replace(
                        &mut const_uses,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(client, const_uses, "constantuses", "", "").await;
                    }));
                }
            }

            InternalMessage::CfDeps(mut deps) => {
                for dep in deps.drain(..) {
                    key.clear();
                    let (from, to, maybe) = match dep {
                        Edge::Certain(from, to) => (from, to, 0),
                        Edge::Maybe(from, to) => (from, to, 1),
                    };
                    let _ = write!(key, "{}", from);
                    let to_start = key.len();
                    let _ = write!(key, "{}", to);
                    let record = DepRecord {
                        from: &key[..to_start],
                        to: &key[to_start..],
                        maybe: Some(maybe),
                        pos: None,
                    };
                    let _ = serde_json::to_writer(&mut cf_deps, &record);
                    let _ = write!(&mut cf_deps, "\n");
                }
                if cf_deps.len() >= HIGH_WATERMARK {
                    let cf_deps = std::mem::replace(
                        &mut cf_deps,
                        Vec::with_capacity(HIGH_WATERMARK + OVERHEAD),
                    );
                    let client = client.clone();
                    tasks.push(tokio::spawn(async move {
                        flush_collection(
                            client,
                            cf_deps,
                            "cfdep",
                            "operationruns",
                            "operationruns",
                        )
                        .await;
                    }));
                }
            }

            InternalMessage::Done => {
                break;
            }
        }
    }

    if ticks.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(client, ticks, "instructionruns", "", "").await;
        }));
    }

    if deltas.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(client, deltas, "operationruns", "", "").await;
        }));
    }

    if const_uses.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(client, const_uses, "constantuses", "", "").await;
        }));
    }

    if value_deps.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(
                client,
                value_deps,
                "inputdep",
                "operationruns",
                "operationruns",
            )
            .await;
        }));
    }

    if addr_deps.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(
                client,
                addr_deps,
                "addrdep",
                "operationruns",
                "operationruns",
            )
            .await;
        }));
    }

    if const_value_deps.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(
                client,
                const_value_deps,
                "constinputdep",
                "operationruns",
                "constantuses",
            )
            .await;
        }));
    }

    if const_addr_deps.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(
                client,
                const_addr_deps,
                "constaddrdep",
                "operationruns",
                "constantuses",
            )
            .await;
        }));
    }

    if cf_deps.len() > 0 {
        let client = client.clone();
        tasks.push(tokio::spawn(async move {
            flush_collection(client, cf_deps, "cfdep", "operationruns", "operationruns").await;
        }));
    }

    for task in tasks.drain(..) {
        let _ = task.await;
    }

    Ok(())
}

async fn flush_collection(
    client: reqwest::Client,
    data: Vec<u8>,
    collection: &str,
    from: &str,
    to: &str,
) {
    let _res = client
        .post(ENDPOINT)
        //.basic_auth("user", Some("password"))
        .version(reqwest::Version::HTTP_11)
        .query(&[
            ("collection", collection),
            ("type", "documents"),
            ("fromPrefix", from),
            ("toPrefix", to),
        ])
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .body(data)
        .send()
        .await;
}

enum InternalMessage {
    Tick(Tick, u64, String),
    Deltas(Vec<(Index, Tick, OperationKind, Delta)>),
    AddrDeps(Vec<Edge>),
    ConstAddrDeps(Vec<ConstEdge>),
    ValueDeps(Vec<(Edge, u8)>),
    ConstValueDeps(Vec<(ConstEdge, u8)>),
    CfDeps(Vec<Edge>),
    Done,
}

#[derive(thiserror::Error, Debug)]
enum InternalError {}

#[derive(Serialize)]
struct TickRecord<'a> {
    #[serde(rename = "_key")]
    key: &'a str,
    runid: u64,
    tick: usize,
    pc: u64,
    disas: &'a str,
}

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

#[derive(Serialize)]
struct ConstRecord<'a> {
    #[serde(rename = "_key")]
    key: &'a str,
    val: Option<u64>,
    raw: Option<&'a str>,
    size: usize,
}

#[derive(Serialize)]
struct DepRecord<'a> {
    #[serde(rename = "_from")]
    from: &'a str,
    #[serde(rename = "_to")]
    to: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    maybe: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pos: Option<u8>,
}

struct PartialPrinter<'a>(&'a [Option<u8>]);

impl std::fmt::Display for PartialPrinter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0.iter().rev() {
            match byte {
                Some(b) => write!(f, "{:02x}", b)?,
                None => write!(f, "??")?,
            }
        }
        Ok(())
    }
}
