use crate::Result;

const MAX_HOSTS: usize = 1_000;
const MAX_FIELD_BYTES: usize = 4_096;
pub const MAX_VAULT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SSH_PASSWORD_BYTES: usize = 1022;
pub const MAX_SHORTCUTS: usize = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandShortcut {
    pub name: String,
    pub command: String,
}

impl CommandShortcut {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty()
            || self.name.len() > 80
            || self.name.chars().any(char::is_control)
        {
            return Err(
                "Enter a shortcut name of up to 80 bytes without control characters.".into(),
            );
        }
        if self.command.trim().is_empty()
            || self.command.len() > MAX_FIELD_BYTES
            || self.command.chars().any(char::is_control)
        {
            return Err(
                "Enter a single-line command of up to 4,096 bytes without control characters."
                    .into(),
            );
        }
        Ok(())
    }
}

// Keep reading the original host-only payload, and version the expanded workspace separately.
pub fn encode_inventory(hosts: &[Host], shortcuts: &[CommandShortcut]) -> Result<Vec<u8>> {
    if shortcuts.len() > MAX_SHORTCUTS {
        return Err("You can save up to 100 custom shortcuts.".into());
    }
    let hosts = encode_hosts(hosts)?;
    let mut bytes = b"SSH-WORKSPACE\x01".to_vec();
    bytes.extend_from_slice(&(hosts.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&hosts);
    bytes.extend_from_slice(&(shortcuts.len() as u32).to_le_bytes());
    for shortcut in shortcuts {
        shortcut.validate()?;
        for field in [&shortcut.name, &shortcut.command] {
            bytes.extend_from_slice(&(field.len() as u32).to_le_bytes());
            bytes.extend_from_slice(field.as_bytes());
        }
    }
    if bytes.len() > MAX_VAULT_BYTES {
        return Err("Workspace exceeds the vault size limit.".into());
    }
    Ok(bytes)
}

pub fn decode_inventory(bytes: &[u8]) -> Result<(Vec<Host>, Vec<CommandShortcut>)> {
    if bytes.starts_with(b"SSH-HOSTS") {
        return Ok((decode_hosts(bytes)?, vec![]));
    }
    if bytes.len() > MAX_VAULT_BYTES {
        return Err("Workspace exceeds the vault size limit.".into());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(14)? != b"SSH-WORKSPACE\x01" {
        return Err("Unsupported workspace format.".into());
    }
    let host_bytes = reader.u32()? as usize;
    let hosts = decode_hosts(reader.take(host_bytes)?)?;
    let count = reader.u32()? as usize;
    if count > MAX_SHORTCUTS {
        return Err("Too many command shortcuts.".into());
    }
    let mut shortcuts = Vec::with_capacity(count);
    for _ in 0..count {
        let shortcut = CommandShortcut {
            name: reader.string()?,
            command: reader.string()?,
        };
        shortcut.validate()?;
        shortcuts.push(shortcut);
    }
    if !reader.finished() {
        return Err("Unexpected data after workspace records.".into());
    }
    Ok((hosts, shortcuts))
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Authentication {
    #[default]
    Key,
    Password,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedPassword {
    pub id: [u8; 16],
    // Remains encrypted even while the inventory is unlocked.
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    // A reference to an existing OpenSSH key; key material is never read here.
    pub identity_path: String,
    pub authentication: Authentication,
    pub password: Option<SavedPassword>,
}

impl Host {
    pub fn validate(&self) -> Result<()> {
        if self.authentication == Authentication::Password && self.password.is_none() {
            return Err("Enter a server password before saving password login.".into());
        }
        if let Some(password) = &self.password
            && !(29..=MAX_SSH_PASSWORD_BYTES + 28).contains(&password.ciphertext.len())
        {
            return Err("Invalid encrypted server password record.".into());
        }
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
    pub const fn command(self) -> &'static str {
        match self {
            Self::System => "uname -a; cat /etc/os-release",
            Self::Uptime => "uptime",
            Self::Disk => "df -h",
            Self::Memory => "free -h",
        }
    }
}

pub const BUILTIN_SHORTCUTS: &[(&str, &str)] = &[
    ("System info", ReadOnlyAction::System.command()),
    ("Uptime", ReadOnlyAction::Uptime.command()),
    ("Disk usage", ReadOnlyAction::Disk.command()),
    ("Memory", ReadOnlyAction::Memory.command()),
    ("CPU info", "lscpu"),
    ("Block devices", "lsblk -f"),
    ("Directory sizes", "du -h --max-depth=1 . | sort -h"),
    (
        "Top CPU processes",
        "ps -eo pid,ppid,user,%cpu,%mem,args --sort=-%cpu | head -n 21",
    ),
    (
        "Top memory processes",
        "ps -eo pid,ppid,user,%mem,%cpu,args --sort=-%mem | head -n 21",
    ),
    ("Logged-in users", "w"),
    ("Last logins", "last -n 20"),
    ("Network addresses", "ip -br address"),
    ("Network routes", "ip route"),
    ("Listening ports", "ss -tuln"),
    ("Network connections", "ss -tun"),
    ("Failed services", "systemctl --failed --no-pager"),
    (
        "Running services",
        "systemctl list-units --type=service --state=running --no-pager",
    ),
    ("Recent system logs", "journalctl -n 100 --no-pager"),
    (
        "Recent system errors",
        "journalctl -p err -n 100 --no-pager",
    ),
    ("Docker containers", "docker ps"),
    ("Docker all containers", "docker ps -a"),
    ("Docker disk usage", "docker system df"),
    ("Docker resource usage", "docker stats --no-stream"),
    ("Compose services", "docker compose ps"),
    ("Kubernetes pods", "kubectl get pods -A -o wide"),
    ("Kubernetes nodes", "kubectl get nodes -o wide"),
    ("Kubernetes deployments", "kubectl get deployments -A"),
    (
        "Kubernetes events",
        "kubectl get events -A --sort-by=.metadata.creationTimestamp | tail -n 51",
    ),
];

// Length-prefixed UTF-8 fields. This codec is versioned and bounds all allocation.
pub fn encode_hosts(hosts: &[Host]) -> Result<Vec<u8>> {
    if hosts.len() > MAX_HOSTS {
        return Err("This prototype supports up to 1,000 hosts.".into());
    }
    let mut bytes = b"SSH-HOSTS\x02".to_vec();
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
        bytes.push(match host.authentication {
            Authentication::Key => 0,
            Authentication::Password => 1,
        });
        if let Some(password) = &host.password {
            bytes.push(1);
            bytes.extend_from_slice(&password.id);
            bytes.extend_from_slice(&(password.ciphertext.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&password.ciphertext);
        } else {
            bytes.push(0);
        }
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
    let magic = reader.take(10)?;
    if &magic[..9] != b"SSH-HOSTS" || !matches!(magic[9], 1 | 2) {
        return Err("Unsupported host record format.".into());
    }
    let count = reader.u32()? as usize;
    if count > MAX_HOSTS {
        return Err("Too many host records.".into());
    }
    let mut hosts = Vec::with_capacity(count);
    for _ in 0..count {
        let mut host = Host {
            name: reader.string()?,
            address: reader.string()?,
            username: reader.string()?,
            identity_path: reader.string()?,
            port: u16::from_le_bytes(reader.take(2)?.try_into().unwrap()),
            authentication: Authentication::Key,
            password: None,
        };
        if magic[9] == 2 {
            host.authentication = match reader.take(1)?[0] {
                0 => Authentication::Key,
                1 => Authentication::Password,
                _ => return Err("Unsupported SSH authentication method.".into()),
            };
            host.password = match reader.take(1)?[0] {
                0 => None,
                1 => {
                    let id = reader.take(16)?.try_into().unwrap();
                    let size = reader.u32()? as usize;
                    if !(29..=MAX_SSH_PASSWORD_BYTES + 28).contains(&size) {
                        return Err("Invalid encrypted server password size.".into());
                    }
                    Some(SavedPassword {
                        id,
                        ciphertext: reader.take(size)?.to_vec(),
                    })
                }
                _ => return Err("Invalid server password presence marker.".into()),
            };
        }
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

    #[test]
    fn builtin_shortcuts_have_unique_names_and_insertable_single_line_commands() {
        let mut names = std::collections::BTreeSet::new();
        for (name, command) in BUILTIN_SHORTCUTS {
            assert!(
                names.insert(name.to_lowercase()),
                "Duplicate shortcut: {name}"
            );
            CommandShortcut {
                name: (*name).into(),
                command: (*command).into(),
            }
            .validate()
            .unwrap();
        }
    }

    #[test]
    fn workspace_shortcuts_round_trip_and_migrate_host_only_inventory() {
        let hosts = vec![host()];
        let shortcuts = vec![CommandShortcut {
            name: "Container status".into(),
            command: "docker ps --format '{{.Names}}'".into(),
        }];
        let bytes = encode_inventory(&hosts, &shortcuts).unwrap();
        assert_eq!(
            decode_inventory(&bytes).unwrap(),
            (hosts.clone(), shortcuts)
        );
        assert_eq!(
            decode_inventory(&encode_hosts(&hosts).unwrap()).unwrap(),
            (hosts, vec![])
        );
        for end in 0..bytes.len() {
            assert!(decode_inventory(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_inventory(&trailing).is_err());
        let mut excessive = encode_inventory(&[], &[]).unwrap();
        let end = excessive.len();
        excessive[end - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_inventory(&excessive).is_err());
    }

    #[test]
    fn shortcuts_reject_control_characters_empty_fields_and_oversized_records() {
        for command in [
            "",
            "   ",
            "uptime\nreboot",
            "uptime\r",
            "\x1b[200~id",
            "echo\0secret",
            "echo\tsecret",
        ] {
            assert!(
                CommandShortcut {
                    name: "Test".into(),
                    command: command.into()
                }
                .validate()
                .is_err()
            );
        }
        for name in ["", "  ", "Test\n"] {
            assert!(
                CommandShortcut {
                    name: name.into(),
                    command: "uptime".into()
                }
                .validate()
                .is_err()
            );
        }
        let mut shortcut = CommandShortcut {
            name: "Test".into(),
            command: "x".repeat(MAX_FIELD_BYTES + 1),
        };
        assert!(shortcut.validate().is_err());
        shortcut.command = "uptime".into();
        assert!(encode_inventory(&[], &vec![shortcut; MAX_SHORTCUTS + 1]).is_err());
    }

    fn host() -> Host {
        Host {
            name: "Production \u{2014} Dhaka".into(),
            address: "server.example.com".into(),
            port: 2222,
            username: "deploy".into(),
            identity_path: "C:\\Users\\Owner\\SSH Keys\\id_ed25519".into(),
            authentication: Authentication::Key,
            password: None,
        }
    }

    #[test]
    fn inventory_round_trips_unicode_and_paths() {
        let mut password_host = host();
        password_host.authentication = Authentication::Password;
        password_host.password = Some(SavedPassword {
            id: [4; 16],
            ciphertext: vec![8; 48],
        });
        let hosts = vec![host(), password_host];
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

    #[test]
    fn legacy_key_inventory_loads_and_upgrades_without_losing_hosts() {
        let bytes = b"SSH-HOSTS\x01\x01\0\0\0\x04\0\0\0Test\x0b\0\0\0example.com\x06\0\0\0deploy\0\0\0\0\x16\0";
        let hosts = decode_hosts(bytes).unwrap();
        assert_eq!(hosts[0].authentication, Authentication::Key);
        assert_eq!(hosts[0].name, "Test");
        assert!(hosts[0].password.is_none());
        let upgraded = encode_hosts(&hosts).unwrap();
        assert_eq!(&upgraded[..10], b"SSH-HOSTS\x02");
        assert_eq!(decode_hosts(&upgraded).unwrap(), hosts);
    }

    #[test]
    fn rejects_unknown_authentication_and_missing_password() {
        let mut bytes = encode_hosts(&[host()]).unwrap();
        let authentication_position = bytes.len() - 2;
        bytes[authentication_position] = 42;
        assert!(decode_hosts(&bytes).is_err());
        bytes[authentication_position] = 1;
        assert!(decode_hosts(&bytes).is_err());
    }
}
