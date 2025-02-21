use dataflow_core::analysis::EmulatorOutput;
use dataflow_core::datastore::Datastore;
use dataflow_core::delta::Delta;
use dataflow_core::operation::Operation;
use dataflow_core::oplog::OpLog;
use dataflow_core::plugins::DataflowPlugin;
use dataflow_core::slot::Slot;
use dataflow_core::space::SpaceKind;
use dataflow_core::value::PartialValue;

//use log::trace;

pub type DefaultFloatModel = IEEE754Model;

#[derive(Debug, Copy, Clone)]
pub struct IEEE754Model;

impl IEEE754Model {
    pub fn new() -> Self {
        Self
    }

    fn resolve_input(&self, store: &Datastore, oplog: &OpLog, slot: &mut Slot) {
        if slot.space.kind() == SpaceKind::Constant {
            // See equivalent code in core "analysis" for rationale behind u128 casting.
            slot.value = PartialValue::from(slot.offset as u128);
        }

        slot.value = PartialValue::default();
        let mut has_value = false;

        for (i, address) in slot.as_range().iter().enumerate() {
            if let Some(index) = store.last_modified(&address) {
                if let Some((_, _, delta)) = store.delta(*index) {
                    has_value = true;
                    slot.value.set_or_unset(i, delta.value_at(address));
                }
            }
        }

        if has_value {
            return;
        }

        if slot.space.kind() == SpaceKind::Memory {
            oplog.fill_with_reads(slot);
        }
    }
}

impl DataflowPlugin for IEEE754Model {
    fn on_operation(
        &mut self,
        store: &Datastore,
        oplog: &OpLog,
        op: Operation,
        emu_out: &mut EmulatorOutput,
    ) {
        let op = &op;
        match op {
            Operation::FloatEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                == f32::from_bits(input1.value.as_u32().unwrap()))
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                == f64::from_bits(input1.value.as_u64().unwrap()))
                            .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatNotEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                != f32::from_bits(input1.value.as_u32().unwrap()))
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                != f64::from_bits(input1.value.as_u64().unwrap()))
                            .into();
                        }
                        _ => {}
                    }
                }
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatLess(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                < f32::from_bits(input1.value.as_u32().unwrap()))
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                < f64::from_bits(input1.value.as_u64().unwrap()))
                            .into();
                        }
                        _ => {}
                    }
                }
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatLessEqual(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                <= f32::from_bits(input1.value.as_u32().unwrap()))
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                <= f64::from_bits(input1.value.as_u64().unwrap()))
                            .into();
                        }
                        _ => {}
                    }
                }
                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatNaN(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match input0.size {
                        4 => {
                            output.value = f32::from_bits(input0.value.as_u32().unwrap())
                                .is_nan()
                                .into();
                        }
                        8 => {
                            output.value = f64::from_bits(input0.value.as_u64().unwrap())
                                .is_nan()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatAdd(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);

                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                + f32::from_bits(input1.value.as_u32().unwrap()))
                            .to_bits()
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                + f64::from_bits(input1.value.as_u64().unwrap()))
                            .to_bits()
                            .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatDiv(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);
                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                / f32::from_bits(input1.value.as_u32().unwrap()))
                            .to_bits()
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                / f64::from_bits(input1.value.as_u64().unwrap()))
                            .to_bits()
                            .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatMult(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);
                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                * f32::from_bits(input1.value.as_u32().unwrap()))
                            .to_bits()
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                * f64::from_bits(input1.value.as_u64().unwrap()))
                            .to_bits()
                            .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatSub(op) => {
                let out = op.output();
                let [iaddr0, iaddr1] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);
                let mut input1 = Slot::from(iaddr1);
                self.resolve_input(store, oplog, &mut input1);

                let mut output = Slot::from(out);
                let inputs = (input0.as_complete(), input1.as_complete());
                if let (Some(_), Some(_)) = inputs {
                    assert!(input0.size == input1.size);
                    match input0.size {
                        4 => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap())
                                - f32::from_bits(input1.value.as_u32().unwrap()))
                            .to_bits()
                            .into();
                        }
                        8 => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap())
                                - f64::from_bits(input1.value.as_u64().unwrap()))
                            .to_bits()
                            .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatNeg(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match input0.size {
                        4 => {
                            output.value = (-f32::from_bits(input0.value.as_u32().unwrap()))
                                .to_bits()
                                .into();
                        }
                        8 => {
                            output.value = (-f64::from_bits(input0.value.as_u64().unwrap()))
                                .to_bits()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatAbs(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match input0.size {
                        4 => {
                            output.value = f32::from_bits(input0.value.as_u32().unwrap())
                                .abs()
                                .to_bits()
                                .into();
                        }
                        8 => {
                            output.value = f64::from_bits(input0.value.as_u64().unwrap())
                                .abs()
                                .to_bits()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatSqrt(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match input0.size {
                        4 => {
                            output.value = f32::from_bits(input0.value.as_u32().unwrap())
                                .sqrt()
                                .to_bits()
                                .into();
                        }
                        8 => {
                            output.value = f64::from_bits(input0.value.as_u64().unwrap())
                                .sqrt()
                                .to_bits()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::IntToFloat(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match (input0.size, output.size) {
                        (1, 4) => {
                            output.value = (input0.value.as_i8().unwrap() as f32).to_bits().into();
                        }
                        (2, 4) => {
                            output.value = (input0.value.as_i16().unwrap() as f32).to_bits().into();
                        }
                        (4, 4) => {
                            output.value = (input0.value.as_i32().unwrap() as f32).to_bits().into();
                        }
                        (8, 4) => {
                            output.value = (input0.value.as_i64().unwrap() as f32).to_bits().into();
                        }
                        (1, 8) => {
                            output.value = (input0.value.as_i8().unwrap() as f64).to_bits().into();
                        }
                        (2, 8) => {
                            output.value = (input0.value.as_i16().unwrap() as f64).to_bits().into();
                        }
                        (4, 8) => {
                            output.value = (input0.value.as_i32().unwrap() as f64).to_bits().into();
                        }
                        (8, 8) => {
                            output.value = (input0.value.as_i64().unwrap() as f64).to_bits().into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatToFloat(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match (input0.size, output.size) {
                        (4, 8) => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap()) as f64)
                                .to_bits()
                                .into();
                        }
                        (8, 4) => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap()) as f32)
                                .to_bits()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatToInt(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match (input0.size, output.size) {
                        (4, 1) => {
                            output.value =
                                (f32::from_bits(input0.value.as_u32().unwrap()) as i8).into();
                        }
                        (4, 2) => {
                            output.value =
                                (f32::from_bits(input0.value.as_u32().unwrap()) as i16).into();
                        }
                        (4, 4) => {
                            output.value =
                                (f32::from_bits(input0.value.as_u32().unwrap()) as i32).into();
                        }
                        (4, 8) => {
                            output.value =
                                (f32::from_bits(input0.value.as_u32().unwrap()) as i64).into();
                        }
                        (8, 1) => {
                            output.value =
                                (f64::from_bits(input0.value.as_u64().unwrap()) as i8).into();
                        }
                        (8, 2) => {
                            output.value =
                                (f64::from_bits(input0.value.as_u64().unwrap()) as i16).into();
                        }
                        (8, 4) => {
                            output.value =
                                (f64::from_bits(input0.value.as_u64().unwrap()) as i32).into();
                        }
                        (8, 8) => {
                            output.value =
                                (f64::from_bits(input0.value.as_u64().unwrap()) as i64).into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatCeil(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match input0.size {
                        4 => {
                            output.value = f32::from_bits(input0.value.as_u32().unwrap())
                                .ceil()
                                .to_bits()
                                .into();
                        }
                        8 => {
                            output.value = f64::from_bits(input0.value.as_u64().unwrap())
                                .ceil()
                                .to_bits()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatFloor(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match input0.size {
                        4 => {
                            output.value = f32::from_bits(input0.value.as_u32().unwrap())
                                .floor()
                                .to_bits()
                                .into();
                        }
                        8 => {
                            output.value = f64::from_bits(input0.value.as_u64().unwrap())
                                .floor()
                                .to_bits()
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            Operation::FloatRound(op) => {
                let out = op.output();
                let [iaddr0] = op.inputs();
                let mut input0 = Slot::from(iaddr0);
                self.resolve_input(store, oplog, &mut input0);

                let mut output = Slot::from(out);
                if let Some(_) = input0.as_complete() {
                    match (input0.size, output.size) {
                        (4, 4) => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap()).round()
                                as u32)
                                .into();
                        }
                        (8, 4) => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap()).round()
                                as u32)
                                .into();
                        }
                        (4, 8) => {
                            output.value = (f32::from_bits(input0.value.as_u32().unwrap()).round()
                                as u64)
                                .into();
                        }
                        (8, 8) => {
                            output.value = (f64::from_bits(input0.value.as_u64().unwrap()).round()
                                as u64)
                                .into();
                        }
                        _ => {}
                    }
                }

                emu_out.delta = Some(Delta::Dataflow(output, None));
            }
            _ => {}
        };
    }
}
