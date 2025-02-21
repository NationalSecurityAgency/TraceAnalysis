use ghidra_lifter::Lifter;

#[test]
fn test_no_cache() {
    static PUSH_R15: &'static [u8] = b"\x41\x57";
    static PUSH_R14: &'static [u8] = b"\x41\x56";
    let mut lifter = Lifter::new("x86:LE:64:default:default").unwrap();
    let inslength = lifter.lift(0x1000, PUSH_R15).unwrap();
    assert_eq!(inslength, 2);
    assert_eq!(lifter.getAssembly().to_string_lossy().as_ref(), "PUSH R15");

    lifter.clear();

    let inslength = lifter.lift(0x1000, PUSH_R14).unwrap();
    assert_eq!(inslength, 2);
    assert_eq!(lifter.getAssembly().to_string_lossy().as_ref(), "PUSH R14");
}
