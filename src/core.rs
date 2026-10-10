use crate::Result;

const MAX_HOSTS: usize = 1_000;
const MAX_FIELD_BYTES: usize = 4_096;
pub const MAX_VAULT_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    // A reference to an existing OpenSSH key; key material is never read here.
    pub identity_path: String,
}

impl Host {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.chars().any(char::is_control) {
            return Err("Enter a display name without control characters.".into());
        }
        let address = self.address.as_str();
        if address.is_empty()
            || address.len() > 253
            || address.starts_with(['-', '.'])
            || !address
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".-:".contains(&c))
            || (address.contains(':') && address.parse::<std::net::Ipv6Addr>().is_err())
        {
            return Err("Enter a DNS hostname, IPv4 address, or unbracketed IPv6 address.".into());
        }
        if self.port == 0 {
            return Err("SSH port must be between 1 and 65535.".into());
        }
        if self.username.is_empty()
            || self.username.len() > 64
            || self.username.starts_with('-')
            || !self
                .username
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        {
            return Err(
                "Use a Linux username containing letters, digits, underscores or hyphens.".into(),
            );
        }
        if self.identity_path.chars().any(char::is_control) {
            return Err("The identity path contains a control character.".into());
        }
        for field in [
            &self.name,
            &self.address,
            &self.username,
            &self.identity_path,
        ] {
            if field.len() > MAX_FIELD_BYTES {
                return Err("A host field is too long.".into());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ReadOnlyAction {
    System,
    Uptime,
    Disk,
    Memory,
}

impl ReadOnlyAction {
    pub fn command(self) -> &'static str {
        match self {
            Self::System => "uname -a; cat /etc/os-release",
            Self::Uptime => "uptime",
            Self::Disk => "df -h",
            Self::Memory => "free -h",
        }
    }
}

// Length-prefixed UTF-8 fields. This codec is versioned and bounds all allocation.
pub fn encode_hosts(hosts: &[Host]) -> Result<Vec<u8>> {
    if hosts.len() > MAX_HOSTS {
        return Err("This prototype supports up to 1,000 hosts.".into());
    }
    let mut bytes = b"SSH-HOSTS\x01".to_vec();
    bytes.extend_from_slice(&(hosts.len() as u32).to_le_bytes());
    for host in hosts {
        host.validate()?;
        for field in [
            &host.name,
            &host.address,
            &host.username,
            &host.identity_path,
        ] {
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
        bytes.extend_from_slice(&host.port.to_le_bytes());
    }
    if bytes.len() > MAX_VAULT_BYTES {
        return Err("Host inventory exceeds the vault size limit.".into());
    }
    Ok(bytes)
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub(crate) fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or("Invalid record length.")?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or("Truncated record.")?;
        self.position = end;
        Ok(slice)
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn finished(&self) -> bool {
        self.position == self.bytes.len()
    }

    fn string(&mut self) -> Result<String> {
        let length = self.u32()? as usize;
        if length > MAX_FIELD_BYTES {
            return Err("Host field exceeds size limit.".into());
        }
        String::from_utf8(self.take(length)?.to_vec())
            .map_err(|_| "Invalid UTF-8 in host record.".into())
    }
}

pub fn decode_hosts(bytes: &[u8]) -> Result<Vec<Host>> {
    if bytes.len() > MAX_VAULT_BYTES {
        return Err("Host inventory exceeds size limit.".into());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(10)? != b"SSH-HOSTS\x01" {
        return Err("Unsupported host record format.".into());
    }
    let count = reader.u32()? as usize;
    if count > MAX_HOSTS {
        return Err("Too many host records.".into());
    }
    let mut hosts = Vec::with_capacity(count);
    for _ in 0..count {
        let host = Host {
            name: reader.string()?,
            address: reader.string()?,
            username: reader.string()?,
            identity_path: reader.string()?,
            port: u16::from_le_bytes(reader.take(2)?.try_into().unwrap()),
        };
        host.validate()?;
        hosts.push(host);
    }
    if !reader.finished() {
        return Err("Unexpected data after host records.".into());
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            name: "Production \u{2014} Dhaka".into(),
            address: "server.example.com".into(),
            port: 2222,
            username: "deploy".into(),
            identity_path: "C:\\Users\\Owner\\SSH Keys\\id_ed25519".into(),
        }
    }

    #[test]
    fn inventory_round_trips_unicode_and_paths() {
        let hosts = vec![host()];
        assert_eq!(decode_hosts(&encode_hosts(&hosts).unwrap()).unwrap(), hosts);
    }

    #[test]
    fn rejects_every_truncated_inventory_and_trailing_data() {
        let bytes = encode_hosts(&[host()]).unwrap();
        for end in 0..bytes.len() {
            assert!(decode_hosts(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_hosts(&trailing).is_err());
    }

    #[test]
    fn rejects_option_and_shell_injection_in_targets() {
        for address in [
            "-oProxyCommand=cmd",
            "host;reboot",
            "user@host",
            "host\n",
            "$(id)",
            "a:b",
        ] {
            let mut candidate = host();
            candidate.address = address.into();
            assert!(candidate.validate().is_err(), "{address}");
        }
        for username in ["-root", "root;id", "root@host", "$(id)"] {
            let mut candidate = host();
            candidate.username = username.into();
            assert!(candidate.validate().is_err(), "{username}");
        }
        let mut ipv6 = host();
        ipv6.address = "2001:db8::1".into();
        assert!(ipv6.validate().is_ok());
    }

    #[test]
    fn rejects_unbounded_lengths() {
        let mut bytes = b"SSH-HOSTS\x01".to_vec();
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_hosts(&bytes).is_err());
        let mut bytes = b"SSH-HOSTS\x01".to_vec();
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_hosts(&bytes).is_err());
    }
}
