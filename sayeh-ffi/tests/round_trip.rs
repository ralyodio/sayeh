use sayeh_ffi::{CarrierChoice, hide_password_file, reveal_password_message, scan_message};

#[test]
fn ffi_round_trip_accepts_dense_short_cover() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = (0..500)
        .map(|index| (index as u8).wrapping_mul(73).wrapping_add(19))
        .collect::<Vec<_>>();
    let hidden = hide_password_file(
        "سلام خوبی؟".to_owned(),
        "payload.bin".to_owned(),
        bytes.clone(),
        "ffi test password".to_owned(),
        CarrierChoice::ZeroWidth,
        10,
    )?;
    let scan = scan_message(hidden.text.clone())?;
    assert_eq!(scan.wire_version, 4);
    let opened = reveal_password_message(hidden.text, "ffi test password".to_owned())?;
    assert_eq!(opened.bytes, bytes);
    Ok(())
}

#[test]
fn ffi_accepts_an_empty_message_password() -> Result<(), Box<dyn std::error::Error>> {
    let hidden = sayeh_ffi::hide_password_text(
        "بدون رمز".to_owned(),
        "concealment only".to_owned(),
        String::new(),
        CarrierChoice::ZeroWidth,
        11,
    )?;
    let opened = reveal_password_message(hidden.text, String::new())?;
    assert_eq!(opened.text.as_deref(), Some("concealment only"));
    Ok(())
}
