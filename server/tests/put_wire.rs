use buffa::encoding::{encode_varint, Tag, WireType};
use exoware_server::{
    decode_entry_with_budget, Field, PutEntryCursor, PutParseError, UnknownBudget,
};

fn bytes_field(number: u32, payload: &[u8]) -> Vec<u8> {
    let mut wire = Vec::new();
    Tag::new(number, WireType::LengthDelimited).encode(&mut wire);
    encode_varint(payload.len() as u64, &mut wire);
    wire.extend_from_slice(payload);
    wire
}

#[test]
fn cursor_resumes_from_every_split_without_replaying_complete_fields() {
    let entry = [
        bytes_field(1, b"key"),
        bytes_field(2, b"value"),
        vec![0x18, 1],
    ]
    .concat();
    let wire = [
        vec![0xa0, 1, 0x81, 1],
        bytes_field(1, &entry),
        vec![0x1b, 0x22, 3, b'f', b'o', b'o', 0x1c],
        bytes_field(1, &[]),
    ]
    .concat();

    for split in 0..=wire.len() {
        let mut buffer = Vec::new();
        let mut budget = UnknownBudget::default();
        let initial_budget = budget.remaining();
        let mut entries = Vec::new();
        let mut offsets = Vec::new();
        let mut buffer_start = 0;
        for chunk in [&wire[..split], &wire[split..]] {
            buffer.extend_from_slice(chunk);
            let mut cursor = PutEntryCursor::new(&buffer);
            assert_eq!(cursor.consumed(), 0);
            loop {
                let before = cursor.remaining();
                let position = cursor.consumed();
                let allowance = budget.remaining();
                match cursor.next(&mut budget) {
                    Ok(Some(Field::Entry(entry))) => {
                        let end = buffer_start + cursor.consumed();
                        offsets.push((end - entry.len(), end));
                        let (key, value) = decode_entry_with_budget(entry, &mut budget).unwrap();
                        entries.push((key.to_vec(), value.to_vec()));
                    }
                    Ok(Some(Field::Unknown)) => {}
                    Ok(None) => break,
                    Err(PutParseError::Incomplete) => {
                        assert_eq!(cursor.remaining(), before);
                        assert_eq!(cursor.consumed(), position);
                        assert_eq!(budget.remaining(), allowance);
                        break;
                    }
                    Err(error) => panic!("split {split} failed with {error}"),
                }
            }
            let consumed = cursor.consumed();
            assert_eq!(consumed + cursor.remaining().len(), buffer.len());
            buffer.drain(..consumed);
            buffer_start += consumed;
        }
        assert!(buffer.is_empty());
        assert_eq!(
            entries,
            vec![(b"key".to_vec(), b"value".to_vec()), (vec![], vec![])]
        );
        assert_eq!(budget.remaining(), initial_budget - 4);
        assert_eq!(
            offsets,
            vec![(6, 6 + entry.len()), (wire.len(), wire.len())]
        );
    }
}

#[test]
fn entry_decode_borrows_the_last_fields_and_preserves_declared_boundaries() {
    let wire = [
        bytes_field(2, b"value"),
        bytes_field(1, b"old"),
        bytes_field(1, b"key"),
    ]
    .concat();
    let (key, value) = decode_entry_with_budget(&wire, &mut UnknownBudget::default()).unwrap();
    assert_eq!((key, value), (b"key".as_slice(), b"value".as_slice()));
    assert_eq!(key.as_ptr(), wire[wire.len() - 3..].as_ptr());
    assert_eq!(value.as_ptr(), wire[2..].as_ptr());
    assert_eq!(
        decode_entry_with_budget(&[], &mut UnknownBudget::default()).unwrap(),
        (&[][..], &[][..])
    );

    let truncated_entry = [0x0a, 2, b'k'];
    let envelope = bytes_field(1, &truncated_entry);
    let mut cursor = PutEntryCursor::new(&envelope);
    let mut budget = UnknownBudget::default();
    assert_eq!(
        cursor.next(&mut budget).unwrap(),
        Some(Field::Entry(&truncated_entry))
    );
    assert!(matches!(
        decode_entry_with_budget(&truncated_entry, &mut budget),
        Err(PutParseError::Malformed(_))
    ));

    let mut cursor = PutEntryCursor::new(&envelope[..envelope.len() - 1]);
    let error = cursor.next(&mut budget).unwrap_err();
    assert!(matches!(error, PutParseError::Incomplete));
    assert_eq!(cursor.consumed(), 0);
    assert!(!cursor.remaining().is_empty());
    let error = connectrpc::ConnectError::from(error);
    assert_eq!(error.code, connectrpc::ErrorCode::InvalidArgument);
    assert_eq!(
        error.message.as_deref(),
        Some("failed to decode proto request: unexpected end of buffer")
    );
}

#[test]
fn request_budget_is_shared_by_top_level_fields_and_entry_decoding() {
    let top_level = [0x10, 0];
    let mut cursor = PutEntryCursor::new(&top_level);
    let mut budget = UnknownBudget::default();
    let initial_budget = budget.remaining();
    assert_eq!(cursor.next(&mut budget).unwrap(), Some(Field::Unknown));
    assert_eq!(cursor.next(&mut budget).unwrap(), None);
    assert_eq!(budget.remaining(), initial_budget - 1);

    decode_entry_with_budget(&[0x18, 0], &mut budget).unwrap();
    assert_eq!(budget.remaining(), initial_budget - 2);
}
