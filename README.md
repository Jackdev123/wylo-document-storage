# WDS — Wylo Document Storage

WDS is a local-first vault for important documents, email archives, and report logs. It stores data in the current browser profile and encrypts the complete vault with AES-256-GCM. A key is derived from your passphrase using PBKDF2-HMAC-SHA-256 (310,000 iterations); the passphrase is never saved. The vault automatically locks after five minutes without activity.

## Run locally

Install Node.js 18 or newer, then run:

```powershell
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The built-in server binds only to the loopback interface and serves the application files; it has no API and does not receive vault contents.

## Run with Docker

With Docker Engine and the Compose plugin installed, run:

```powershell
docker compose up --build -d
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). Compose publishes the app to the host loopback interface only by default.

To access WDS directly over your Tailscale network on port 4173, turn off any previously configured Tailscale Serve proxy and bind Docker to the VM's Tailscale IPv4 address:

```bash
sudo tailscale serve --https=443 off
WDS_BIND_ADDRESS="$(tailscale ip -4)" docker compose up --build -d
```

Open `http://<vm-tailscale-ip>:4173` on another device connected to your tailnet. The app is then bound to the VM's Tailscale interface, not all network interfaces. If UFW blocks tailnet traffic, remove any broad `4173/tcp` allow rule and allow the port on `tailscale0` instead:

```bash
sudo ufw delete allow 4173/tcp
sudo ufw allow in on tailscale0 to any port 4173 proto tcp
```

To choose another local port, set `WDS_PORT` before starting Compose. The container runs as an unprivileged user with a read-only root filesystem, drops Linux capabilities, and has no access to vault data: the browser stores the encrypted vault in its own local profile. No data volume is required. To stop WDS, run `docker compose down`.

## Use your vault

- Create a passphrase with at least 12 characters. A memorable multi-word passphrase is a good choice.
- Add documents (optional file attachments up to 10 MB), email messages, and report logs. Search within each section.
- Export an encrypted JSON backup regularly. Restore it using the passphrase used when it was created.
- Lock the vault when you step away. You can also lock it from the sidebar.

## Important security notes

- Your passphrase cannot be reset. If you forget it, the encrypted vault and backups cannot be decrypted.
- Data is tied to this browser profile and device. Clearing browser site data, changing profiles, or losing the device can remove the local vault; keep a backup somewhere safe.
- Backups are encrypted, but anyone with the backup can attempt passphrases offline. Choose a long, unique passphrase and protect backup files.
- The browser must be kept up to date and the device protected. A compromised device or browser extension may access data while the vault is unlocked.
- Automatic crash reports are stored in the encrypted vault only while it is unlocked. WDS does not send telemetry.
- This is a local single-user application, not a hosted multi-user service. Do not expose the local server to a network.
- The Docker image only packages and serves the static application; it does not persist or back up browser data. Back up your encrypted vault from the app itself.# WDS — Wylo Document Storage

WDS is a local-first vault for important documents, email archives, and report logs. It stores data in the current browser profile and encrypts the complete vault with AES-256-GCM. A key is derived from your passphrase using PBKDF2-HMAC-SHA-256 (310,000 iterations); the passphrase is never saved. The vault automatically locks after five minutes without activity.

## Run locally

Install Node.js 18 or newer, then run:

```powershell
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The built-in server binds only to the loopback interface and serves the application files; it has no API and does not receive vault contents.

## Run with Docker

With Docker Engine and the Compose plugin installed, run:

```powershell
docker compose up --build -d
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). Compose publishes the app to the host loopback interface only. To choose another local port, set `WDS_PORT` before starting Compose. The container runs as an unprivileged user with a read-only root filesystem, drops Linux capabilities, and has no access to vault data: the browser stores the encrypted vault in its own local profile. No data volume is required. To stop WDS, run `docker compose down`.

## Use your vault

- Create a passphrase with at least 12 characters. A memorable multi-word passphrase is a good choice.
- Add documents (optional file attachments up to 10 MB), email messages, and report logs. Search within each section.
- Export an encrypted JSON backup regularly. Restore it using the passphrase used when it was created.
- Lock the vault when you step away. You can also lock it from the sidebar.

## Important security notes

- Your passphrase cannot be reset. If you forget it, the encrypted vault and backups cannot be decrypted.
- Data is tied to this browser profile and device. Clearing browser site data, changing profiles, or losing the device can remove the local vault; keep a backup somewhere safe.
- Backups are encrypted, but anyone with the backup can attempt passphrases offline. Choose a long, unique passphrase and protect backup files.
- The browser must be kept up to date and the device protected. A compromised device or browser extension may access data while the vault is unlocked.
- Automatic crash reports are stored in the encrypted vault only while it is unlocked. WDS does not send telemetry.
- This is a local single-user application, not a hosted multi-user service. Do not expose the local server to a network.
- The Docker image only packages and serves the static application; it does not persist or back up browser data. Back up your encrypted vault from the app itself.
