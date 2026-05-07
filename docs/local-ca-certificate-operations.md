# Local CA and Certificate Operations

This document describes the current local certificate authority workflow in this
project and calls out the pieces that still need implementation.

The local setup is useful when you want to issue MTC certificates without a
DigiCert Private CA or MariaDB. The current `config.yaml` is already configured
for local-only issuance:

- `ca_db.enabled: false`
- `local_ca.enabled: true`
- `local_ca.mtc_mode: true`
- `acme.enabled: true`
- MTC HTTP API on `http://localhost:8080`
- ACME API on `https://localhost:8443` when `acme.tls_cert` and
  `acme.tls_key` are present

## 1. Create the Local CA

Build the project and generate the keys used by the bridge:

```bash
make build
make generate-key
make generate-local-ca
```

This creates:

- `keys/cosigner.key`: Ed25519 key used to sign checkpoints.
- `keys/local-ca.key`: ECDSA P-256 private key for the local CA.
- `keys/local-ca.pem`: self-signed local CA certificate.

The local CA generator always writes `keys/local-ca.key` and
`keys/local-ca.pem`. It uses the hard-coded subject `MTC Demo CA`, `US`.

To trust locally issued legacy certificates in a client, install or pass
`keys/local-ca.pem` as the trust anchor. MTC-spec certificates use the MTC proof
trust model and `signatureAlgorithm = id-alg-mtcProof`; many normal X.509 tools
will not treat them as ordinary CA-signed certificates.

### Not Implemented Yet

- There is no CLI flag to choose the local CA subject, validity, output path, or
  key algorithm during `make generate-local-ca`.
- There is no rotation workflow for replacing `keys/local-ca.key` or
  `keys/cosigner.key`.
- There is no documented trust-store installer for macOS, Windows, Linux,
  Java, or browsers.

## 2. Start the Local Service

For a local process, make sure PostgreSQL is available with the values from
`config.yaml`, then run:

```bash
make build
./bin/mtc-bridge -config config.yaml
```

Useful checks:

```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/checkpoint
```

For Docker Compose, generate the keys first because the compose file mounts the
`keys/` directory read-only:

```bash
make build
make generate-key
make generate-local-ca
docker compose up -d postgres mtc-bridge
docker compose logs -f mtc-bridge
```

### Not Implemented Yet

- The compose file starts both `mtc-bridge` and `acme-server` services from the
  same binary/config. Since the binary already starts both the main HTTP API and
  the ACME API when `acme.enabled: true`, this split should be cleaned up or
  documented as two distinct configs.
- `config.yaml` points ACME TLS at `./acme-keys/acme-cert.pem` and
  `./acme-keys/acme-key.pem`, while `gen-demo-cert.sh` writes
  `acme-cert.pem` and `acme-key.pem` in the repo root. Align these paths before
  relying on Docker HTTPS.

## 3. Create a Certificate

### Fast Standalone MTC Certificate Demo

The simplest local certificate path is the standalone MTC-spec demo:

```bash
make demo-mtc
```

This builds a spec-style certificate where:

- `signatureAlgorithm = id-alg-mtcProof`
- the certificate serial is the Merkle leaf index
- the `signatureValue` contains the binary MTC proof
- the proof is signatureless in the current demo

The demo writes its temporary certificate to `/tmp/mtc-spec-cert.pem`, verifies
it, and then removes it.

To keep a generated cert for inspection:

```bash
make build
./bin/demo-embedded-cert -mtc-mode -domain demo.example.com -output /tmp/mtc-spec-cert.pem
./bin/mtc-verify-cert -cert /tmp/mtc-spec-cert.pem
```

### Legacy Embedded-Proof Certificate Demo

Legacy mode embeds the Merkle inclusion proof in a non-critical X.509 extension
with OID `1.3.6.1.4.1.99999.1.1`:

```bash
make demo-embedded
```

To keep the output:

```bash
make build
./bin/demo-embedded-cert -domain demo.example.com -output /tmp/mtc-legacy-cert.pem
./bin/mtc-verify-cert -cert /tmp/mtc-legacy-cert.pem
```

### ACME Issuance

The ACME server implements account creation, order creation, `http-01`
authorization, CSR finalize, and certificate download. With
`local_ca.enabled: true`, finalize appends the certificate entry directly to the
local issuance log, creates an immediate checkpoint, computes the inclusion
proof, and stores the final certificate chain on the ACME order.

The full ACME flow requires JWS-signed ACME requests. The repository currently
points users to the conformance tool for an automated flow:

```bash
make build
./bin/mtc-conformance -url http://localhost:8080 -acme-url https://localhost:8443 -verbose
```

If TLS is disabled in `config.yaml`, use:

```bash
./bin/mtc-conformance -url http://localhost:8080 -acme-url http://localhost:8443 -verbose
```

### Not Implemented Yet

- `demo-acme.sh` does not complete the ACME order flow; it stops before JWS
  account/order/finalize requests.
- There is no simple first-party CLI command like
  `mtc-bridge issue-cert --domain example.test --out cert.pem`.
- MTC-spec local ACME issuance currently builds signatureless MTC proofs
  (`Signatures: nil`). Signed proof issuance with embedded cosigner signatures
  is not wired into this path yet.
- The MTC-spec certificate verifier uses structural proof validation by default;
  CLI support for loading landmarks or cosigner public keys is not exposed yet.

## 4. Verify a Certificate

The verifier auto-detects both supported certificate formats:

```bash
./bin/mtc-verify-cert -cert /path/to/cert.pem
```

For a running bridge, also compare against the live checkpoint:

```bash
./bin/mtc-verify-cert -cert /path/to/cert.pem -bridge-url http://localhost:8080
```

For certificates already in the bridge log, fetch an inclusion proof directly:

```bash
curl -s "http://localhost:8080/proof/inclusion?index=1" | python3 -m json.tool
```

or, if you know the stored serial:

```bash
curl -s "http://localhost:8080/proof/inclusion?serial=<SERIAL_HEX>" | python3 -m json.tool
```

The inclusion proof response contains:

- `leaf_index`
- `tree_size`
- `leaf_hash`
- `proof`
- `root_hash`
- `checkpoint`

You can also fetch consistency proofs:

```bash
curl -s "http://localhost:8080/proof/consistency?old=1&new=2" | python3 -m json.tool
```

### Not Implemented Yet

- `mtc-verify-cert` does not currently fetch `/landmarks` or accept a landmark
  file for signatureless verification.
- `mtc-verify-cert` does not currently accept cosigner public keys for full
  cryptographic verification of signed MTC proofs.
- The verifier reports present cosigner signatures, but full signature checking
  is not wired through the CLI yet.

## 5. Distribute Landmarks

Landmarks are the signatureless trust anchors for MTC verification:

```text
tree_size -> root_hash
```

The store and handler code support these read APIs:

```bash
curl -s http://localhost:8080/landmarks | python3 -m json.tool
curl -s http://localhost:8080/landmark/<TREE_SIZE> | python3 -m json.tool
```

The intended JSON shape is:

```json
[
  {
    "tree_size": 123,
    "root_hash": "hex-encoded-root",
    "checkpoint_id": 1,
    "created_at": "2026-05-05T12:00:00Z"
  }
]
```

For a specific landmark, the response also includes `signatures`.

Recommended distribution model:

1. Designate a checkpoint as a landmark.
2. Publish the `(tree_size, root_hash)` pair over an authenticated channel.
3. Clients pin or cache that landmark.
4. Clients verify signatureless certificates by recomputing the subtree root
   and comparing it with the pinned landmark for `proof.End`.

### Not Implemented Yet

- The main HTTP mux does not mount `/landmarks` or `/landmark/{tree_size}` even
  though `internal/tlogtiles.Handler` registers those routes. Add these routes
  in `cmd/mtc-bridge/main.go`.
- Landmark persistence exists (`SaveLandmark`, `ListLandmarks`,
  `GetLandmark`), and `Batcher.DesignateLandmark` exists, but there is no CLI,
  admin action, scheduled job, or public API to designate a landmark.
- There is no export format for a signed landmark bundle that clients can
  consume offline.
- There is no client-side landmark cache or verification path in
  `mtc-verify-cert`.

## 6. Reject or Revoke Certificates

There are two different concepts here.

### Reject During Issuance

The ACME server currently rejects:

- malformed JWS requests
- unsupported identifier types other than `dns`
- orders finalized before authorization is `ready`
- CSRs that do not contain every requested identifier
- failed `http-01` validation when `auto_approve_challenge: false`
- internal local CA, log append, checkpoint, proof, or storage failures

These failures set the ACME challenge or order to `invalid` and return ACME
errors to the client.

### Revoke After Issuance

For DigiCert CA mode, revocation tracking is implemented by polling the CA
database for `certificate.is_revoked = 1`, mapping serial numbers to Merkle log
indices, and storing entries in `revoked_indices`.

Check the revocation bitmap:

```bash
curl -s http://localhost:8080/revocation | wc -c
```

The admin UI and assertion bundles also include revoked status when the
revocation is known.

### Not Implemented Yet

- Local CA mode has no revoke endpoint, CLI, CRL, or OCSP responder.
- There is no manual `reject certificate` or `deny domain` policy engine for
  local issuance.
- There is no admin UI action to mark an entry revoked or rejected.
- Revocation is tracked as an MTC bitmap, but normal TLS clients will not
  consume it automatically.
- There is no reject list distribution format for relying parties.

## Implementation Checklist

- Mount `/landmarks` and `/landmark/{tree_size}` in `cmd/mtc-bridge/main.go`.
- Add a CLI/admin/API operation to designate the latest checkpoint as a
  landmark.
- Add `mtc-verify-cert` options for `--landmarks <file-or-url>` and
  `--cosigner-key`.
- Finish `demo-acme.sh` or add a small first-party ACME issuance CLI.
- Add local CA revocation/rejection operations and expose the result through
  `/revocation`, admin UI, and certificate/assertion status.
- Align ACME TLS certificate paths between `config.yaml`, `gen-demo-cert.sh`,
  and `docker-compose.yml`.
