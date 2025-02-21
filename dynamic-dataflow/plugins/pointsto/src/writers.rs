use super::*;
use csv::Writer;
use serde::Serialize;
use std::env;
use std::fmt::Write;
use std::path::Path;
use std::sync::mpsc::Receiver;

#[derive(Clone)]
pub(super) enum Message {
    PointsTo((Index, Index, u64)),
    Done,
}

fn derive_trace_info() -> (String, u64, String) {
    let campaign_id = match env::var("CAMPAIGN_ID") {
        Ok(val) => val,
        Err(_) => "CAMPAIGN".to_owned(),
    };

    let run_id: u64 = match env::var("RUN_ID") {
        Ok(val) => val.parse().unwrap_or(0),
        Err(_) => 0,
    };

    let trace_name = match env::var("TRACE_NAME") {
        Ok(val) => val,
        Err(_) => "TRACE".to_owned(),
    };

    return (campaign_id, run_id, trace_name);
}

pub(super) fn write_pointsto<P: AsRef<Path>>(chan: Receiver<Message>, prefix: P) {
    #[derive(Serialize)]
    struct PointsToRecord<'a> {
        #[serde(rename = "_from")]
        from: &'a str,
        #[serde(rename = "_to")]
        to: &'a str,
        offset: u64,
    }

    let (campaign_id, run_id, trace_name) = derive_trace_info();
    let key_prefix = format!("{}_{}_{}_", campaign_id, run_id, trace_name);

    let mut src_buffer = String::new();
    let mut dst_buffer = String::new();

    let prefix = prefix.as_ref();
    let mut out = Writer::from_path(prefix.join("pointsto.csv")).unwrap();

    while let Ok(msg) = chan.recv() {
        match msg {
            Message::PointsTo((from, to, offset)) => {
                write!(src_buffer, "operations/{}{}", key_prefix, from).unwrap();
                write!(dst_buffer, "operations/{}{}", key_prefix, to).unwrap();

                let record = PointsToRecord {
                    from: src_buffer.as_str(),
                    to: dst_buffer.as_str(),
                    offset,
                };

                let _ = out.serialize(record);

                src_buffer.clear();
                dst_buffer.clear();
            }
            Message::Done => {
                break;
            }
        }
    }

    out.flush().unwrap();
}
