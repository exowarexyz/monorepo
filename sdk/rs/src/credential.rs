//! The API key a client presents, and what a rejection tells the caller to do about it.
//!
//! A deployment behind a load balancer authenticates every RPC, and one without a load balancer
//! authenticates none, so a client cannot know from its configuration whether a credential is
//! required. It carries whatever it has and explains itself when a call comes back rejected.

use std::fmt;

use crate::{ClientError, ConnectError, ErrorCode};

/// Environment variable read for the API key when none is set on the builder.
pub const API_KEY_ENV: &str = "EXOWARE_API_KEY";

/// The API key, held so that it is never printed.
///
/// The credential authorizes every RPC this client makes, so a `Debug` of the builder must not
/// leak it into a log.
#[derive(Clone, Default)]
pub(crate) struct ApiKey(pub(crate) String);

impl fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Whether this client sends a credential with every request.
///
/// Decided once when the client is built, then carried to each site that can raise an RPC error.
/// A rejection is the only place the distinction matters and the least able to see it, since an
/// endpoint reports the same code whether a credential was missing or merely refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Credential {
    Sent,
    Absent,
    /// Configured through the environment, but not sendable as an HTTP header value.
    Unusable,
}

/// Builds the Authorization header for a key, or `None` if the key cannot be one.
///
/// Marked sensitive so the credential cannot reach a log or a Debug of the client.
pub(crate) fn bearer_header(key: &str) -> Option<http::HeaderValue> {
    let mut value = http::HeaderValue::from_str(&format!("Bearer {key}")).ok()?;
    value.set_sensitive(true);
    Some(value)
}

impl Credential {
    /// What to do about an unauthenticated rejection. The two cases share no advice, which is
    /// the reason this is threaded through at all.
    ///
    /// Whoever reads this may be running a binary they did not build, so neither case names an
    /// API. `Absent` means nothing was configured in code either, so the environment variable is
    /// something the reader can act on.
    const fn remedy(self) -> &'static str {
        match self {
            Self::Absent => concat!(
                "This endpoint requires a credential and none was sent. The EXOWARE_API_KEY ",
                "environment variable supplies one"
            ),
            Self::Sent => concat!(
                "The credential sent with this request was refused. It may have expired, or ",
                "been issued for a different deployment, or lack the scope this call needs"
            ),
            Self::Unusable => concat!(
                "The EXOWARE_API_KEY environment variable is set to a value that cannot be an ",
                "HTTP header, so no credential was sent. Remove any control or non-ASCII ",
                "characters from it"
            ),
        }
    }
}

pub(crate) fn client_error_from_connect(
    mut err: ConnectError,
    credential: Credential,
) -> ClientError {
    err.message = err.message.take().and_then(without_html_body);
    if err.code == ErrorCode::Unauthenticated {
        let remedy = credential.remedy();
        err.message = Some(match err.message.take() {
            Some(message) => format!("{message}. {remedy}"),
            None => remedy.to_string(),
        });
    }
    ClientError::Rpc(Box::new(err))
}

/// Drops an HTML error page from a message, keeping whatever preceded it.
fn without_html_body(message: String) -> Option<String> {
    let lowercase = message.to_ascii_lowercase();
    let Some(start) = ["<html", "<!doctype"]
        .iter()
        .filter_map(|marker| lowercase.find(marker))
        .min()
    else {
        return Some(message);
    };

    let kept = message[..start].trim_end().trim_end_matches(':').trim_end();
    (!kept.is_empty()).then(|| kept.to_string())
}

/// The 401 body an ALB serves when it rejects a token, verbatim. Shared with the builder tests
/// in `lib.rs`, which check that a client built from an unusable key explains itself.
#[cfg(test)]
pub(crate) const PROXY_REJECTION: &str = "HTTP error 401: <html>\r\n<head><title>401 Authorization Required</title></head>\r\n<body>\r\n<center><h1>401 Authorization Required</h1></center>\r\n</body>\r\n</html>\r\n";

#[cfg(test)]
mod tests {
    use super::*;

    fn rejection(credential: Credential) -> String {
        client_error_from_connect(
            ConnectError::new(ErrorCode::Unauthenticated, PROXY_REJECTION),
            credential,
        )
        .to_string()
    }

    #[test]
    fn proxy_rejection_keeps_the_status_and_drops_the_page() {
        let err = client_error_from_connect(
            ConnectError::new(ErrorCode::Unauthenticated, PROXY_REJECTION),
            Credential::Sent,
        );
        let rendered = err.to_string();
        assert_eq!(err.rpc_code(), Some(ErrorCode::Unauthenticated));
        assert!(!rendered.contains('<'), "kept markup: {rendered}");
        assert!(rendered.contains("HTTP error 401"), "{rendered}");
    }

    #[test]
    fn a_missing_credential_is_told_how_to_supply_one() {
        let rendered = rejection(Credential::Absent);
        assert!(rendered.contains("none was sent"), "{rendered}");
        assert!(rendered.contains(API_KEY_ENV), "{rendered}");
    }

    /// The reader may not control the binary, so no rejection may point at a Rust API.
    #[test]
    fn no_remedy_names_an_api() {
        for credential in [Credential::Sent, Credential::Absent, Credential::Unusable] {
            let rendered = rejection(credential);
            assert!(!rendered.contains("StoreClient"), "{rendered}");
            assert!(!rendered.contains("::"), "{rendered}");
        }
    }

    /// A client that sent a credential needs to hear why one it already has failed, so it must
    /// not be told to set the variable it already set.
    #[test]
    fn a_refused_credential_is_told_why_rather_than_how_to_set_one() {
        let rendered = rejection(Credential::Sent);
        assert!(rendered.contains("refused"), "{rendered}");
        assert!(rendered.contains("expired"), "{rendered}");
        assert!(!rendered.contains(API_KEY_ENV), "{rendered}");
    }

    #[test]
    fn other_codes_carry_no_credential_remedy() {
        let err = client_error_from_connect(
            ConnectError::new(ErrorCode::NotFound, "no such key"),
            Credential::Absent,
        );
        assert_eq!(err.to_string(), "RPC error (not_found: no such key)");
    }

    #[test]
    fn html_body_recognized_with_a_doctype_and_when_it_is_the_whole_message() {
        assert_eq!(
            without_html_body("HTTP error 502: <!DOCTYPE html><html></html>".to_string()),
            Some("HTTP error 502".to_string())
        );
        assert_eq!(without_html_body("<html>bare</html>".to_string()), None);
    }

    #[test]
    fn a_service_message_survives_untouched() {
        // Service errors are the common case, and nothing about them should be trimmed.
        let message = "key not found: a < b";
        assert_eq!(
            without_html_body(message.to_string()),
            Some(message.to_string())
        );
    }

    #[test]
    fn a_key_becomes_a_sensitive_bearer_header() {
        let value = bearer_header("token-abc").unwrap();
        assert_eq!(value, "Bearer token-abc");

        // set_sensitive is what keeps the credential out of any log that debugs the transport.
        assert!(!format!("{value:?}").contains("token-abc"));
    }

    #[test]
    fn a_key_that_cannot_be_a_header_yields_no_header() {
        assert!(bearer_header("has\nnewline").is_none());
    }
}
