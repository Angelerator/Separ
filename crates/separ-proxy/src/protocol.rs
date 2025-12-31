//! PostgreSQL wire protocol handling
//!
//! Implements message parsing and construction for the PostgreSQL frontend/backend protocol.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;

/// PostgreSQL message types (frontend to backend)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendMessage {
    /// Password message
    PasswordMessage,
    /// Query
    Query,
    /// Parse
    Parse,
    /// Bind
    Bind,
    /// Execute
    Execute,
    /// Describe
    Describe,
    /// Close
    Close,
    /// Sync
    Sync,
    /// Flush
    Flush,
    /// Terminate
    Terminate,
    /// CopyData
    CopyData,
    /// CopyDone
    CopyDone,
    /// CopyFail
    CopyFail,
    /// SASL initial response
    SaslInitialResponse,
    /// SASL response
    SaslResponse,
    /// Unknown
    Unknown(u8),
}

impl FrontendMessage {
    pub fn from_type_byte(b: u8) -> Self {
        match b {
            b'p' => Self::PasswordMessage,
            b'Q' => Self::Query,
            b'P' => Self::Parse,
            b'B' => Self::Bind,
            b'E' => Self::Execute,
            b'D' => Self::Describe,
            b'C' => Self::Close,
            b'S' => Self::Sync,
            b'H' => Self::Flush,
            b'X' => Self::Terminate,
            b'd' => Self::CopyData,
            b'c' => Self::CopyDone,
            b'f' => Self::CopyFail,
            _ => Self::Unknown(b),
        }
    }
}

/// PostgreSQL message types (backend to frontend)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendMessage {
    /// Authentication request
    Authentication,
    /// Parameter status
    ParameterStatus,
    /// Backend key data
    BackendKeyData,
    /// Ready for query
    ReadyForQuery,
    /// Row description
    RowDescription,
    /// Data row
    DataRow,
    /// Command complete
    CommandComplete,
    /// Error response
    ErrorResponse,
    /// Notice response
    NoticeResponse,
    /// Empty query response
    EmptyQueryResponse,
    /// Parse complete
    ParseComplete,
    /// Bind complete
    BindComplete,
    /// Close complete
    CloseComplete,
    /// No data
    NoData,
    /// Parameter description
    ParameterDescription,
    /// Copy in response
    CopyInResponse,
    /// Copy out response
    CopyOutResponse,
    /// Copy both response
    CopyBothResponse,
    /// Copy data
    CopyData,
    /// Copy done
    CopyDone,
    /// Notification response
    NotificationResponse,
    /// Unknown
    Unknown(u8),
}

impl BackendMessage {
    pub fn from_type_byte(b: u8) -> Self {
        match b {
            b'R' => Self::Authentication,
            b'S' => Self::ParameterStatus,
            b'K' => Self::BackendKeyData,
            b'Z' => Self::ReadyForQuery,
            b'T' => Self::RowDescription,
            b'D' => Self::DataRow,
            b'C' => Self::CommandComplete,
            b'E' => Self::ErrorResponse,
            b'N' => Self::NoticeResponse,
            b'I' => Self::EmptyQueryResponse,
            b'1' => Self::ParseComplete,
            b'2' => Self::BindComplete,
            b'3' => Self::CloseComplete,
            b'n' => Self::NoData,
            b't' => Self::ParameterDescription,
            b'G' => Self::CopyInResponse,
            b'H' => Self::CopyOutResponse,
            b'W' => Self::CopyBothResponse,
            b'd' => Self::CopyData,
            b'c' => Self::CopyDone,
            b'A' => Self::NotificationResponse,
            _ => Self::Unknown(b),
        }
    }

    pub fn type_byte(&self) -> u8 {
        match self {
            Self::Authentication => b'R',
            Self::ParameterStatus => b'S',
            Self::BackendKeyData => b'K',
            Self::ReadyForQuery => b'Z',
            Self::RowDescription => b'T',
            Self::DataRow => b'D',
            Self::CommandComplete => b'C',
            Self::ErrorResponse => b'E',
            Self::NoticeResponse => b'N',
            Self::EmptyQueryResponse => b'I',
            Self::ParseComplete => b'1',
            Self::BindComplete => b'2',
            Self::CloseComplete => b'3',
            Self::NoData => b'n',
            Self::ParameterDescription => b't',
            Self::CopyInResponse => b'G',
            Self::CopyOutResponse => b'H',
            Self::CopyBothResponse => b'W',
            Self::CopyData => b'd',
            Self::CopyDone => b'c',
            Self::NotificationResponse => b'A',
            Self::Unknown(b) => *b,
        }
    }
}

/// Authentication request types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthRequest {
    /// Ok - authentication successful
    Ok,
    /// Kerberos V5
    KerberosV5,
    /// Cleartext password
    CleartextPassword,
    /// MD5 password with salt
    Md5Password { salt: [u8; 4] },
    /// SCRAM-SHA-256
    ScramSha256,
    /// SCRAM-SHA-256-PLUS
    ScramSha256Plus,
    /// SASL continue
    SaslContinue { data: Bytes },
    /// SASL final
    SaslFinal { data: Bytes },
    /// Unknown
    Unknown { auth_type: i32 },
}

/// Startup message parameters
#[derive(Debug, Clone)]
pub struct StartupMessage {
    pub protocol_version: i32,
    pub parameters: Vec<(String, String)>,
}

impl StartupMessage {
    /// Get the user parameter
    pub fn user(&self) -> Option<&str> {
        self.parameters.iter()
            .find(|(k, _)| k == "user")
            .map(|(_, v)| v.as_str())
    }

    /// Get the database parameter
    pub fn database(&self) -> Option<&str> {
        self.parameters.iter()
            .find(|(k, _)| k == "database")
            .map(|(_, v)| v.as_str())
    }

    /// Get an arbitrary parameter
    pub fn get(&self, key: &str) -> Option<&str> {
        self.parameters.iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parse a startup message
pub fn parse_startup_message(data: &[u8]) -> io::Result<StartupMessage> {
    if data.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Startup message too short"));
    }

    let mut buf = &data[..];
    let _length = buf.get_i32();
    let protocol_version = buf.get_i32();

    let mut parameters = Vec::new();
    
    while buf.has_remaining() {
        let key = read_cstring(&mut buf)?;
        if key.is_empty() {
            break;
        }
        let value = read_cstring(&mut buf)?;
        parameters.push((key, value));
    }

    Ok(StartupMessage {
        protocol_version,
        parameters,
    })
}

/// Parse a password message
pub fn parse_password_message(data: &[u8]) -> io::Result<String> {
    if data.len() < 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Password message too short"));
    }

    let mut buf = &data[1..]; // Skip message type
    let _length = buf.get_i32();
    
    read_cstring(&mut buf)
}

/// Build an authentication request message
pub fn build_auth_request(request: &AuthRequest) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u8(b'R'); // Authentication message type
    
    match request {
        AuthRequest::Ok => {
            buf.put_i32(8); // Length
            buf.put_i32(0); // AuthenticationOk
        }
        AuthRequest::CleartextPassword => {
            buf.put_i32(8); // Length
            buf.put_i32(3); // AuthenticationCleartextPassword
        }
        AuthRequest::Md5Password { salt } => {
            buf.put_i32(12); // Length
            buf.put_i32(5); // AuthenticationMD5Password
            buf.put_slice(salt);
        }
        AuthRequest::ScramSha256 => {
            let mechanism = b"SCRAM-SHA-256\0";
            buf.put_i32(4 + 4 + mechanism.len() as i32); // Length
            buf.put_i32(10); // AuthenticationSASL
            buf.put_slice(mechanism);
            buf.put_u8(0); // End of mechanism list
        }
        AuthRequest::SaslContinue { data } => {
            buf.put_i32(4 + 4 + data.len() as i32);
            buf.put_i32(11); // AuthenticationSASLContinue
            buf.put_slice(data);
        }
        AuthRequest::SaslFinal { data } => {
            buf.put_i32(4 + 4 + data.len() as i32);
            buf.put_i32(12); // AuthenticationSASLFinal
            buf.put_slice(data);
        }
        _ => {
            buf.put_i32(8);
            buf.put_i32(0);
        }
    }
    
    buf
}

/// Build an error response message
pub fn build_error_response(
    severity: &str,
    code: &str,
    message: &str,
) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u8(b'E'); // Error response
    
    // Build fields
    let mut fields = BytesMut::new();
    fields.put_u8(b'S'); // Severity
    fields.put_slice(severity.as_bytes());
    fields.put_u8(0);
    fields.put_u8(b'C'); // SQLSTATE code
    fields.put_slice(code.as_bytes());
    fields.put_u8(0);
    fields.put_u8(b'M'); // Message
    fields.put_slice(message.as_bytes());
    fields.put_u8(0);
    fields.put_u8(0); // End of fields
    
    buf.put_i32(4 + fields.len() as i32);
    buf.put(fields);
    
    buf
}

/// Build a parameter status message
pub fn build_parameter_status(name: &str, value: &str) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u8(b'S');
    
    let length = 4 + name.len() + 1 + value.len() + 1;
    buf.put_i32(length as i32);
    buf.put_slice(name.as_bytes());
    buf.put_u8(0);
    buf.put_slice(value.as_bytes());
    buf.put_u8(0);
    
    buf
}

/// Build ready for query message
pub fn build_ready_for_query(status: u8) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u8(b'Z');
    buf.put_i32(5);
    buf.put_u8(status);
    buf
}

/// Build backend key data message
pub fn build_backend_key_data(process_id: i32, secret_key: i32) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.put_u8(b'K');
    buf.put_i32(12);
    buf.put_i32(process_id);
    buf.put_i32(secret_key);
    buf
}

/// Read a null-terminated string from a buffer
fn read_cstring(buf: &mut &[u8]) -> io::Result<String> {
    let mut bytes = Vec::new();
    
    while buf.has_remaining() {
        let b = buf.get_u8();
        if b == 0 {
            break;
        }
        bytes.push(b);
    }
    
    String::from_utf8(bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

