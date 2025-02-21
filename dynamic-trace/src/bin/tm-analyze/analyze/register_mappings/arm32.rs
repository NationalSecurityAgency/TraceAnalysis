use phf::phf_map;

pub static ARM32_REG: phf::Map<&'static str, &'static str> = phf_map! {
    "cpsr" => "cpsr",
    "d0" => "d0",
    "d1" => "d1",
    "d10" => "d10",
    "d11" => "d11",
    "d12" => "d12",
    "d13" => "d13",
    "d14" => "d14",
    "d15" => "d15",
    "d16" => "d16",
    "d17" => "d17",
    "d18" => "d18",
    "d19" => "d19",
    "d2" => "d2",
    "d20" => "d20",
    "d21" => "d21",
    "d22" => "d22",
    "d23" => "d23",
    "d24" => "d24",
    "d25" => "d25",
    "d26" => "d26",
    "d27" => "d27",
    "d28" => "d28",
    "d29" => "d29",
    "d3" => "d3",
    "d30" => "d30",
    "d31" => "d31",
    "d4" => "d4",
    "d5" => "d5",
    "d6" => "d6",
    "d7" => "d7",
    "d8" => "d8",
    "d9" => "d9",
    "fpexc" => "fpexc",
    "fpscr" => "fpscr",
    "fpsid" => "fpsid",
    "lr" => "lr",
    "pc" => "pc",
    "q0" => "q0",
    "q1" => "q1",
    "q10" => "q10",
    "q11" => "q11",
    "q12" => "q12",
    "q13" => "q13",
    "q14" => "q14",
    "q15" => "q15",
    "q2" => "q2",
    "q3" => "q3",
    "q4" => "q4",
    "q5" => "q5",
    "q6" => "q6",
    "q7" => "q7",
    "q8" => "q8",
    "q9" => "q9",
    "r0" => "r0",
    "r1" => "r1",
    "r10" => "r10",
    "r11" => "r11",
    "r12" => "r12",
    "r2" => "r2",
    "r3" => "r3",
    "r4" => "r4",
    "r5" => "r5",
    "r6" => "r6",
    "r7" => "r7",
    "r8" => "r8",
    "r9" => "r9",
    "sp" => "sp",
};
