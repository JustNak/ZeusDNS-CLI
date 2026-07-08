# Minisign key management for ZeusDNS-CLI releases

The ZeusDNS updater uses [minisign](https://github.com/jedisct1/minisign) to verify
release binaries before installing them. This document describes how the project
owner generates, protects, and uses the signing keypair.

## Prerequisites

Install minisign on your local machine:

- **macOS**: `brew install minisign`
- **Linux**: `sudo apt install minisign` or `sudo dnf install minisign`
- **Windows**: Download a pre-built binary from the [releases page](https://github.com/jedisct1/minisign/releases)

## Generate a keypair

```bash
minisign -G
```

You will be prompted for a password to protect the secret key. **Choose a strong
password and store it in a password manager.**

This creates two files in the current directory:

- `minisign.key` — the **secret key** (keep this PRIVATE; never commit it)
- `minisign.pub` — the **public key** (embed this in the updater source)

## Embed the public key in the updater

1. Read the content of `minisign.pub`:

   ```bash
   cat minisign.pub
   ```

   It looks like:

   ```
   untrusted comment: minisign public key <hex-id>
   RWR<base64-encoded key>
   ```

2. Open `updater/minisign.go` and replace the `EmbeddedMinisignPubkey` constant
   with the **entire content** of `minisign.pub` (both lines):

   ```go
   // TODO: owner — replace with the full content of your minisign.pub file.
   const EmbeddedMinisignPubkey = `untrusted comment: minisign public key <hex-id>
   RWR<base64-encoded key>`
   ```

   Use a raw string literal (backticks) so the newlines are preserved.

3. Commit and push. **Do NOT commit `minisign.key`** — add it to your
   `.gitignore` or keep it outside the repository entirely.

## Sign a release

### Locally (manual test)

```bash
minisign -S -m zeusdns_1.2.3_windows_amd64.zip -s /path/to/minisign.key
```

This creates `zeusdns_1.2.3_windows_amd64.zip.minisig`.

### CI (automated, recommended)

The `.github/workflows/release.yml` includes a signing step that runs
automatically when a `v*` tag is pushed. To enable it:

1. **Export your secret key from the password-protected format**:

   ```bash
   # The raw minisign key starts after the password line.
   # You can extract it by running:
   minisign -R -s minisign.key -p /dev/stdout
   # Then copy the raw key content (the RWS... line).
   ```

   Alternatively, the content of `minisign.key` is the file itself (the first
   line is `untrusted comment: minisign secret key`; the second line is the
   base64-encoded secret key). Copy the **entire file content** (both lines).

2. **Add it as a GitHub Encrypted Secret**:

   - Go to your repository → Settings → Secrets and variables → Actions
   - Click **New repository secret**
   - Name: `MINISIGN_PRIVATE_KEY`
   - Value: paste the **entire content of `minisign.key`** (including the
     `untrusted comment:` header)
   - Click **Add secret**

3. Push a `v*` tag. The CI will:

   - Build the binaries and create release zips
   - Install `minisign` on the runner via `apt`
   - Sign each zip with the secret key
   - Upload both the zips and `.minisig` files to the GitHub release

   If the `MINISIGN_PRIVATE_KEY` secret is not set (e.g., PRs from forks),
   the signing step is skipped. The updater will then refuse to install
   unsigned binaries unless `EmbeddedMinisignPubkey` is left empty (which is
   the default), in which case the updater also fails-closed rather than
   silently skipping verification — see the next section.

## ⚠ Fail-closed behaviour

**If `EmbeddedMinisignPubkey` is empty (the default), the updater refuses to
install any update.** This is intentional: the owner must explicitly configure
minisign before the self-update path can be used.

When you are ready to distribute signed releases:

1. Generate your keypair (one-time).
2. Paste the public key into `updater/minisign.go`.
3. Add the secret key to GitHub Secrets.
4. Push a release tag.

## Key rotation

If the secret key is compromised:

1. Generate a new keypair: `minisign -G`
2. Update `EmbeddedMinisignPubkey` in the source with the new public key.
3. Sign all future releases with the new secret key.
4. Revoke the old key by removing it from GitHub Secrets and adding the
   compromised key's ID to a note in the release notes so users can verify
   they have the latest pubkey.

> **Security note**: minisign uses Ed25519 (signature) + BLAKE2b (pre-hash for
> files >1GB). The secret key is encrypted at rest with your password. GitHub
> encrypts the CI secret at rest and only exposes it to runner processes.
