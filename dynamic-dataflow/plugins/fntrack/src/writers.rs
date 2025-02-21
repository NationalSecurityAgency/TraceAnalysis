use super::*;
use csv::Writer;
use serde::Serialize;
use std::env;
use std::fmt::Write;
use std::path::Path;
use std::sync::mpsc::Receiver;

#[derive(Clone)]
pub(super) enum Message {
    FunctionRun(
        (
            Index,           // startindex,
            Option<Address>, // pc,
            Address,         // firstpc,
            Tick,            // starttick,
            Option<Index>,   // endindex,
            Option<Address>, // callsite,
            Option<usize>,   // retval,
            i64,             // stackdepth,
            Option<Address>, // stackptr,
            Option<Index>,   // retdep,
            Vec<ContextDep>, // context,
            Vec<Index>,      // calls,
            Vec<Tick>,       // ticks,
        ),
    ), // startindex, pc, starttick, endindex, callsite, retval, stackdepth, stackptr, retdep, context, calls, ticks
    //FunctionTick((Tick, Index)), // tick, startindex
    SyscallRun(
        (
            Tick,
            Option<usize>,
            Option<usize>,
            Vec<ContextDep>,
            Option<Index>,
        ),
    ), // tick, number, retval, context, callerstartindex
    Buffer((Index, Address, u64, bool, Vec<u8>)), // functionrunindex, address, size, iswrite, data (aso computes BufferOf edges)
    Done,
}

fn derive_trace_info() -> (String, u64, String) {
    let campaign_id = match env::var("CAMPAIGN_ID") {
        Ok(val) => val,
        Err(_) => "CAMPAIGN".to_owned(),
    };

    let run_id: u64 = match env::var("RUN_ID") {
        Ok(val) => match val.parse() {
            Ok(val) => val,
            Err(_) => 0,
        },
        Err(_) => 0,
    };

    let trace_name = match env::var("TRACE_NAME") {
        Ok(val) => val,
        Err(_) => "TRACE".to_owned(),
    };

    return (campaign_id, run_id, trace_name);
}

// pub(super) fn write_functionticks<P: AsRef<Path>>(chan: Receiver<Message>, prefix: P) {
//     #[derive(Serialize)]
//     struct DepRecord<'a> {
//         #[serde(rename = "_from")]
//         from: &'a str,
//         #[serde(rename = "_to")]
//         to: &'a str
//     }

//     let (campaign_id, run_id, trace_name) = derive_trace_info();
//     let key_prefix = format!("{}_{}_{}_", campaign_id, run_id, trace_name);
//     let mut src_buffer = String::new();
//     let mut dst_buffer = String::new();

//     let prefix = prefix.as_ref();
//     let mut out = Writer::from_path(prefix.join("functionticks.csv")).unwrap();

//     while let Ok(msg) = chan.recv() {
//         match msg {
//             Message::FunctionTick((tick, startindex)) => {
//                 write!(src_buffer, "instructioruns/{}{}", key_prefix, tick as usize).unwrap();
//                 write!(dst_buffer, "functionruns/{}{}", key_prefix, startindex as usize).unwrap();
// 		let deprecord = DepRecord {
// 		    from: src_buffer.as_str(),
// 		    to: dst_buffer.as_str()
//                 };
//                 let _ = out.serialize(deprecord);
// 		src_buffer.clear();
// 		dst_buffer.clear();
//             },
//             Message::Done => { break; },
//             _ => {},
//         }
//     }

//     out.flush().unwrap();
// }

pub(super) fn write_functionruns<P: AsRef<Path>>(chan: Receiver<Message>, prefix: P) {
    #[derive(Serialize)]
    struct FunctionRunRecord<'a> {
        #[serde(rename = "_key")]
        key: &'a str,
        campaignid: &'a str,
        runid: u64,
        traceid: &'a str,
        startindex: usize,
        pc: Option<u64>,
        firstpc: u64,
        starttick: usize,
        endindex: Option<usize>,
        callsite: Option<u64>,
        retval: Option<usize>,
        stackdepth: i64,
        stackptr: Option<u64>,
    }

    #[derive(Serialize)]
    struct DepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
    }

    #[derive(Serialize)]
    struct ContextRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        bank: usize,
        offset: u64,
    }

    let (campaign_id, run_id, trace_name) = derive_trace_info();
    let mut key_buffer = String::new();

    let mut src_buffer = String::new();
    let mut retdep_dst_buffer = String::new();
    let mut context_dst_buffer = String::new();
    let mut ticks_src_buffer = String::new();
    let mut calls_dst_buffer = String::new();

    let prefix = prefix.as_ref();
    let mut out = Writer::from_path(prefix.join("functionruns.csv")).unwrap();
    let mut ticksout = Writer::from_path(prefix.join("functionticks.csv")).unwrap();
    let mut retdepout = Writer::from_path(prefix.join("retdeps.csv")).unwrap();
    let mut contextout = Writer::from_path(prefix.join("functionruncontext.csv")).unwrap();
    let mut callsout = Writer::from_path(prefix.join("calls.csv")).unwrap();

    while let Ok(msg) = chan.recv() {
        match msg {
            Message::FunctionRun((
                startindex,
                pc,
                firstpc,
                starttick,
                endindex,
                callsite,
                retval,
                stackdepth,
                stackptr,
                retdep,
                mut context,
                mut calls,
                mut ticks,
            )) => {
                write!(key_buffer, "{}", startindex).unwrap();
                write!(src_buffer, "functionruns/{}", startindex).unwrap();
                if let Some(retdep) = retdep {
                    write!(retdep_dst_buffer, "operationruns/{}", retdep).unwrap();
                }

                let stack_base: Option<u64> = match stackptr {
                    Some(addr) => Some(addr.offset()),
                    None => None,
                };

                let startpc = match pc {
                    Some(somepc) => Some(somepc.offset()),
                    None => None,
                };

                let cs = match callsite {
                    Some(somscs) => Some(somscs.offset()),
                    None => None,
                };

                let record = FunctionRunRecord {
                    key: key_buffer.as_str(),
                    campaignid: &campaign_id,
                    runid: run_id,
                    traceid: &trace_name,
                    startindex,
                    pc: startpc,
                    firstpc: firstpc.offset(),
                    starttick: starttick as usize,
                    endindex,
                    callsite: cs,
                    retval,
                    stackdepth: stackdepth as i64,
                    stackptr: stack_base,
                };

                let _ = out.serialize(record);

                if retdep.is_some() {
                    let retdeprecord = DepRecord {
                        from: src_buffer.as_str(),
                        to: retdep_dst_buffer.as_str(),
                    };
                    let _ = retdepout.serialize(retdeprecord);
                }

                for ctx in context.drain(..) {
                    write!(context_dst_buffer, "operationruns/{}", ctx.index).unwrap();
                    let contextrecord = ContextRecord {
                        from: src_buffer.as_str(),
                        to: context_dst_buffer.as_str(),
                        bank: ctx.bank as usize,
                        offset: ctx.offset,
                    };
                    let _ = contextout.serialize(contextrecord);
                    context_dst_buffer.clear();
                }

                for t in ticks.drain(..) {
                    write!(ticks_src_buffer, "instructionruns/{}", t as usize).unwrap();
                    let deprecord = DepRecord {
                        from: ticks_src_buffer.as_str(),
                        to: src_buffer.as_str(),
                    };
                    let _ = ticksout.serialize(deprecord);
                    ticks_src_buffer.clear();
                }

                for idx in calls.drain(..) {
                    write!(calls_dst_buffer, "functionruns/{}", idx).unwrap();
                    let callsrecord = DepRecord {
                        from: src_buffer.as_str(),
                        to: calls_dst_buffer.as_str(),
                    };
                    let _ = callsout.serialize(callsrecord);
                    calls_dst_buffer.clear();
                }

                key_buffer.clear();
                src_buffer.clear();
                retdep_dst_buffer.clear();
            }
            Message::Done => {
                break;
            }
            _ => {}
        }
    }

    out.flush().unwrap();
}

pub(super) fn write_syscallruns<P: AsRef<Path>>(chan: Receiver<Message>, prefix: P) {
    #[derive(Serialize)]
    struct SyscallRunRecord<'a> {
        #[serde(rename = "_key")]
        key: &'a str,
        campaignid: &'a str,
        runid: u64,
        traceid: &'a str,
        tick: u64,
        number: Option<usize>,
        retval: Option<usize>,
    }

    #[derive(Serialize)]
    struct DepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
    }

    #[derive(Serialize)]
    struct ContextRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        bank: usize,
        offset: u64,
    }

    let (campaign_id, run_id, trace_name) = derive_trace_info();
    let mut key_buffer = String::new();

    let mut src_buffer = String::new();
    let mut context_dst_buffer = String::new();
    let mut caller_dst_buffer = String::new();

    let prefix = prefix.as_ref();
    let mut out = Writer::from_path(prefix.join("syscallruns.csv")).unwrap();
    let mut contextout = Writer::from_path(prefix.join("syscallruncontext.csv")).unwrap();
    let mut callerout = Writer::from_path(prefix.join("syscallruncalls.csv")).unwrap();

    while let Ok(msg) = chan.recv() {
        match msg {
            Message::SyscallRun((tick, number, retval, mut context, startindex)) => {
                write!(key_buffer, "{}", tick).unwrap();
                write!(src_buffer, "syscallruns/{}", tick).unwrap();

                let record = SyscallRunRecord {
                    key: key_buffer.as_str(),
                    campaignid: &campaign_id,
                    runid: run_id,
                    traceid: &trace_name,
                    tick,
                    number,
                    retval,
                };
                let _ = out.serialize(record);

                for ctx in context.drain(..) {
                    write!(context_dst_buffer, "operationruns/{}", ctx.index).unwrap();
                    let contextrecord = ContextRecord {
                        from: src_buffer.as_str(),
                        to: context_dst_buffer.as_str(),
                        bank: ctx.bank as usize,
                        offset: ctx.offset,
                    };
                    let _ = contextout.serialize(contextrecord);
                    context_dst_buffer.clear();
                }

                if let Some(caller) = startindex {
                    write!(caller_dst_buffer, "functionruns/{}", caller).unwrap();
                    let deprecord = DepRecord {
                        from: src_buffer.as_str(),
                        to: caller_dst_buffer.as_str(),
                    };
                    let _ = callerout.serialize(deprecord);
                    caller_dst_buffer.clear();
                }
                key_buffer.clear();
                src_buffer.clear();
            }
            Message::Done => {
                break;
            }
            _ => {}
        }
    }

    out.flush().unwrap();
}

// Buffer((Index, Address, usize, Vec<u8>)), // functionrunindex, address, size, data (aso computes BufferOf edges)
pub(super) fn write_buffers<P: AsRef<Path>>(chan: Receiver<Message>, prefix: P) {
    #[derive(Serialize)]
    struct BufferRecord<'a> {
        #[serde(rename = "_key")]
        key: &'a str,
        campaignid: &'a str,
        runid: u64,
        traceid: &'a str,
        address: u64,
        size: u64,
        iswrite: bool,
        data: String,
    }

    #[derive(Serialize)]
    struct DepRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
    }

    let (campaign_id, run_id, trace_name) = derive_trace_info();
    let mut key_buffer = String::new();
    let mut src_buffer = String::new();
    let mut dst_buffer = String::new();
    let mut data_buffer = String::new();

    let prefix = prefix.as_ref();
    let mut out = Writer::from_path(prefix.join("buffers.csv")).unwrap();
    let mut edgesout = Writer::from_path(prefix.join("bufferof.csv")).unwrap();

    while let Ok(msg) = chan.recv() {
        match msg {
            Message::Buffer((index, addr, size, iswrite, data)) => {
                write!(
                    key_buffer,
                    "{}_{}_{}",
                    index,
                    addr.offset(),
                    if iswrite { 1 } else { 0 }
                )
                .unwrap();
                write!(
                    src_buffer,
                    "buffers/{}_{}_{}",
                    index,
                    addr.offset(),
                    if iswrite { 1 } else { 0 }
                )
                .unwrap();
                write!(dst_buffer, "functionruns/{}", index).unwrap();

                for b in data.iter() {
                    let _ = write!(data_buffer, "{:02x}", b);
                }

                let record = BufferRecord {
                    key: key_buffer.as_str(),
                    campaignid: &campaign_id,
                    runid: run_id,
                    traceid: &trace_name,
                    address: addr.offset(),
                    size,
                    iswrite,
                    data: data_buffer.as_str().to_string(),
                };
                let _ = out.serialize(record);

                let edgerecord = DepRecord {
                    from: src_buffer.as_str(),
                    to: dst_buffer.as_str(),
                };
                let _ = edgesout.serialize(edgerecord);

                src_buffer.clear();
                dst_buffer.clear();
                key_buffer.clear();
                data_buffer.clear();
            }
            Message::Done => {
                break;
            }
            _ => {}
        }
    }

    out.flush().unwrap();
}
