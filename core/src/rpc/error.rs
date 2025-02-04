use std::fmt::Display;
use tonic::Status;

pub(crate) fn _expected_msg_got_error(msg: Status) -> Status {
    Status::invalid_argument(format!("Expected message, got error: {msg}"))
}

pub(crate) fn expected_msg_got_none(msg: &str) -> impl (Fn() -> Status) + '_ {
    move || Status::invalid_argument(format!("Expected {msg} but received None"))
}

pub(crate) fn input_ended_prematurely() -> Status {
    Status::invalid_argument("Input stream ended prematurely")
}

pub(crate) fn sighash_stream_ended_prematurely() -> Status {
    Status::internal("Sighash stream ended prematurely")
}

pub(crate) fn output_stream_ended_prematurely() -> Status {
    Status::internal("Output stream ended prematurely".to_string())
}

pub(crate) fn sighash_stream_failed(msg: Status) -> Status {
    Status::internal(format!("Sighash stream failed: {msg}"))
}

pub(crate) fn invalid_argument<'a, T: std::error::Error + Send + Sync + 'static + Display>(
    field: &'a str,
    msg: &'a str,
) -> impl 'a + Fn(T) -> Status {
    move |e| Status::invalid_argument(format!("Failed to parse {field}: {msg}\n{e}"))
}
