use crate::carrier::CarrierKind;
use crate::crypto::{Argon2Params, NONCE_BYTES, SALT_BYTES};
use crate::{EMBEDDING_REVISION, Error, Result, WIRE_VERSION};

pub const MAGIC: [u8; 4] = *b"SYH4";
pub const MAX_CONTAINER_PAYLOAD: usize = 16 * 1024 * 1024;
pub const PASSWORD_HEADER_BYTES: usize = 68;
pub const CONTACT_HEADER_BYTES: usize = 72;
const FIXED_HEADER_BYTES: usize = 16;

/// Password-specific authenticated header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordHeader {
    parameters: Argon2Params,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
}

impl PasswordHeader {
    pub const fn new(
        parameters: Argon2Params,
        salt: [u8; SALT_BYTES],
        nonce: [u8; NONCE_BYTES],
    ) -> Self {
        Self {
            parameters,
            salt,
            nonce,
        }
    }

    pub const fn parameters(&self) -> Argon2Params {
        self.parameters
    }

    pub const fn salt(&self) -> &[u8; SALT_BYTES] {
        &self.salt
    }

    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }
}

/// Contact-specific authenticated header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactHeader {
    ephemeral_public: [u8; 32],
    nonce: [u8; NONCE_BYTES],
}

impl ContactHeader {
    pub const fn new(ephemeral_public: [u8; 32], nonce: [u8; NONCE_BYTES]) -> Self {
        Self {
            ephemeral_public,
            nonce,
        }
    }

    pub const fn ephemeral_public(&self) -> &[u8; 32] {
        &self.ephemeral_public
    }

    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }
}

/// Mode-specific fields cannot exist beside fields from another mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeHeader {
    Password(PasswordHeader),
    Contact(ContactHeader),
}

impl ModeHeader {
    pub const fn id(&self) -> u8 {
        match self {
            Self::Password(_) => 1,
            Self::Contact(_) => 2,
        }
    }

    pub const fn header_len(&self) -> usize {
        match self {
            Self::Password(_) => PASSWORD_HEADER_BYTES,
            Self::Contact(_) => CONTACT_HEADER_BYTES,
        }
    }

    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        match self {
            Self::Password(header) => header.nonce(),
            Self::Contact(header) => header.nonce(),
        }
    }
}

/// Parsed, validated header used by all downstream operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    carrier: CarrierKind,
    compressed: bool,
    error_correction: bool,
    mode: ModeHeader,
}

impl Header {
    pub const fn new(carrier: CarrierKind, compressed: bool, mode: ModeHeader) -> Self {
        Self {
            carrier,
            compressed,
            error_correction: false,
            mode,
        }
    }

    pub const fn carrier(&self) -> CarrierKind {
        self.carrier
    }

    pub const fn compressed(&self) -> bool {
        self.compressed
    }

    pub const fn error_correction(&self) -> bool {
        self.error_correction
    }

    pub const fn mode(&self) -> &ModeHeader {
        &self.mode
    }

    pub const fn nonce(&self) -> &[u8; NONCE_BYTES] {
        self.mode.nonce()
    }

    pub fn encode(&self, payload_len: usize) -> Result<Vec<u8>> {
        if payload_len > MAX_CONTAINER_PAYLOAD {
            return Err(Error::ContentTooLarge);
        }
        let header_len = self.mode.header_len();
        let mut bytes = Vec::with_capacity(header_len);
        bytes.extend_from_slice(&MAGIC);
        bytes.push(WIRE_VERSION);
        bytes.push(EMBEDDING_REVISION);
        bytes.push(self.mode.id());
        bytes.push(self.carrier.id());
        let flags = u8::from(self.compressed) | (u8::from(self.error_correction) << 1);
        bytes.push(flags);
        bytes.push(0);
        bytes.extend_from_slice(
            &u16::try_from(header_len)
                .map_err(|_| Error::LengthOverflow)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(
            &u32::try_from(payload_len)
                .map_err(|_| Error::LengthOverflow)?
                .to_be_bytes(),
        );

        match &self.mode {
            ModeHeader::Password(header) => {
                bytes.extend_from_slice(&header.parameters().memory_kib().to_be_bytes());
                bytes.extend_from_slice(&header.parameters().passes().to_be_bytes());
                bytes.push(header.parameters().lanes());
                bytes.extend_from_slice(&[0u8; 3]);
                bytes.extend_from_slice(header.salt());
                bytes.extend_from_slice(header.nonce());
            }
            ModeHeader::Contact(header) => {
                bytes.extend_from_slice(header.ephemeral_public());
                bytes.extend_from_slice(header.nonce());
            }
        }
        if bytes.len() != header_len {
            return Err(Error::LengthOverflow);
        }
        Ok(bytes)
    }
}

/// A sealed container is distinct from opened plaintext at the type level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedContainer {
    header: Header,
    aad: Vec<u8>,
    payload: Vec<u8>,
}

impl SealedContainer {
    pub fn new(header: Header, payload: Vec<u8>) -> Result<Self> {
        let aad = header.encode(payload.len())?;
        Ok(Self {
            header,
            aad,
            payload,
        })
    }

    /// Parses hostile bytes once into a canonical sealed value.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(b"ZWS3") {
            return Err(Error::LegacyV3Refused);
        }
        let mut reader = Reader::new(bytes);
        if reader.array::<4>()? != MAGIC {
            return Err(Error::InvalidContainer);
        }
        let version = reader.byte()?;
        if version != WIRE_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let revision = reader.byte()?;
        if revision != EMBEDDING_REVISION {
            return Err(Error::UnsupportedEmbedding(revision));
        }
        let mode = reader.byte()?;
        let carrier = CarrierKind::from_id(reader.byte()?)?;
        let flags = reader.byte()?;
        if flags & !0b11 != 0 || reader.byte()? != 0 {
            return Err(Error::InvalidContainer);
        }
        let compressed = flags & 1 != 0;
        if flags & 2 != 0 {
            return Err(Error::UnsupportedFeature("error correction"));
        }
        let header_len = usize::from(reader.u16()?);
        let payload_len = usize::try_from(reader.u32()?).map_err(|_| Error::LengthOverflow)?;
        if payload_len > MAX_CONTAINER_PAYLOAD {
            return Err(Error::ContentTooLarge);
        }

        let mode = match mode {
            1 => {
                if header_len != PASSWORD_HEADER_BYTES {
                    return Err(Error::InvalidContainer);
                }
                let parameters = Argon2Params::new(reader.u32()?, reader.u32()?, reader.byte()?)?;
                if reader.array::<3>()? != [0u8; 3] {
                    return Err(Error::InvalidContainer);
                }
                ModeHeader::Password(PasswordHeader::new(
                    parameters,
                    reader.array::<SALT_BYTES>()?,
                    reader.array::<NONCE_BYTES>()?,
                ))
            }
            2 => {
                if header_len != CONTACT_HEADER_BYTES {
                    return Err(Error::InvalidContainer);
                }
                ModeHeader::Contact(ContactHeader::new(
                    reader.array::<32>()?,
                    reader.array::<NONCE_BYTES>()?,
                ))
            }
            _ => return Err(Error::InvalidContainer),
        };
        if reader.position() != header_len || header_len < FIXED_HEADER_BYTES {
            return Err(Error::InvalidContainer);
        }
        let total = header_len
            .checked_add(payload_len)
            .ok_or(Error::LengthOverflow)?;
        if bytes.len() < total {
            return Err(Error::Truncated);
        }
        if bytes.len() != total {
            return Err(Error::InvalidContainer);
        }
        let aad = bytes.get(..header_len).ok_or(Error::Truncated)?.to_vec();
        let payload = bytes
            .get(header_len..total)
            .ok_or(Error::Truncated)?
            .to_vec();
        let header = Header {
            carrier,
            compressed,
            error_correction: false,
            mode,
        };
        if header.encode(payload_len)? != aad {
            return Err(Error::InvalidContainer);
        }
        Ok(Self {
            header,
            aad,
            payload,
        })
    }

    pub const fn header(&self) -> &Header {
        &self.header
    }

    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn marshal(&self) -> Result<Vec<u8>> {
        let total = self
            .aad
            .len()
            .checked_add(self.payload.len())
            .ok_or(Error::LengthOverflow)?;
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(&self.aad);
        bytes.extend_from_slice(&self.payload);
        Ok(bytes)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or(Error::Truncated)?;
        self.position = self.position.checked_add(1).ok_or(Error::LengthOverflow)?;
        Ok(byte)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let end = self.position.checked_add(N).ok_or(Error::LengthOverflow)?;
        let slice = self.bytes.get(self.position..end).ok_or(Error::Truncated)?;
        let mut value = [0u8; N];
        value.copy_from_slice(slice);
        self.position = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}
