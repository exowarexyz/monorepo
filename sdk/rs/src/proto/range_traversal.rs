//! Range query traversal direction from `RangeRequest.mode`.

use crate::query::TraversalMode;
use buffa::EnumValue;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeTraversalDirection {
    Forward,
    Reverse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RangeTraversalModeError {
    /// Unknown `i32` on the wire (not FORWARD=0 or REVERSE=1).
    UnknownWireValue(i32),
}

/// Maps `RangeRequest.mode` (default **forward** when unset on the wire).
pub fn parse_range_traversal_direction(
    mode: EnumValue<TraversalMode>,
) -> Result<RangeTraversalDirection, RangeTraversalModeError> {
    match mode.as_known() {
        Some(TraversalMode::TRAVERSAL_MODE_FORWARD) => Ok(RangeTraversalDirection::Forward),
        Some(TraversalMode::TRAVERSAL_MODE_REVERSE) => Ok(RangeTraversalDirection::Reverse),
        None => Err(RangeTraversalModeError::UnknownWireValue(mode.to_i32())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_and_reverse_are_zero_and_one() {
        assert_eq!(
            EnumValue::from(TraversalMode::TRAVERSAL_MODE_FORWARD).to_i32(),
            0
        );
        assert_eq!(
            EnumValue::from(TraversalMode::TRAVERSAL_MODE_REVERSE).to_i32(),
            1
        );
    }

    #[test]
    fn rejects_unknown_wire_value() {
        let ev = EnumValue::<TraversalMode>::from(99);
        assert!(ev.is_unknown());
        assert_eq!(
            parse_range_traversal_direction(ev),
            Err(RangeTraversalModeError::UnknownWireValue(99))
        );
    }

    #[test]
    fn accepts_forward_and_reverse() {
        assert_eq!(
            parse_range_traversal_direction(EnumValue::from(TraversalMode::TRAVERSAL_MODE_FORWARD)),
            Ok(RangeTraversalDirection::Forward)
        );
        assert_eq!(
            parse_range_traversal_direction(EnumValue::from(TraversalMode::TRAVERSAL_MODE_REVERSE)),
            Ok(RangeTraversalDirection::Reverse)
        );
    }
}
