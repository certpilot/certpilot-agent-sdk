# The CertPilot agent signing scheme

`certpilot-agent-v1`

This document is the contract. It is written so that an agent can be
implemented in any language without reading the Go in `agentauth/`, and it is
normative where the two disagree — except that the Go is what actually runs, so
report the disagreement.

**An agent does not have to be the CertPilot agent.** A Go binary is one
implementation. A Kubernetes operator, a Python daemon, a PowerShell scheduled
task and an embedded device are all equally valid agents if they produce these
bytes.

---

## 1. What this is and is not

The agent's credential is an **Ed25519 private key generated on the host** and
never transmitted. The core stores only the public half, so a database that
leaks yields nothing that can impersonate an agent. That is the property a
bearer token does not have, and bearer tokens on five hundred hosts are the
thing this product exists to stop organisations doing.

This **authenticates**. It does not encrypt. Use TLS.

**Why signatures and not mTLS:** the core is routinely deployed behind a reverse
proxy, and client-certificate authentication terminates at that proxy. What
reaches the application is a header, and a header is forged by anything that can
reach the core directly. An application-layer signature is verified by the
process that acts on the request, so it survives every proxy, ingress and
service mesh in between.

---

## 2. Headers

Every signed request carries exactly three:

| Header | Value |
|:---|:---|
| `X-CertPilot-Agent` | the agent id the core issued at enrolment |
| `X-CertPilot-Timestamp` | Unix time in **seconds**, base-10, no fraction |
| `X-CertPilot-Signature` | the Ed25519 signature, **standard** base64 **with padding** |

Standard base64, not URL-safe: `+` and `/`, and `=` padding to a multiple of
four. A 64-byte Ed25519 signature always encodes to 88 characters ending in
`==`.

---

## 3. The signing string

Five fields joined by a single line feed (`U+000A`). No trailing newline. No
carriage returns. UTF-8.

```
certpilot-agent-v1\n
<METHOD>\n
<path>\n
<unix-seconds>\n
<lowercase hex SHA-256 of the request body>
```

Field by field:

1. **`certpilot-agent-v1`** — the scheme name, literal.

   It is *inside* the signed bytes rather than merely alongside them. A verifier
   that one day supports two schemes must not be talked into checking a v2
   signature under v1 rules by an attacker who controls a header.

2. **`<METHOD>`** — the HTTP method, **uppercased** (`POST`, not `post`).

3. **`<path>`** — the request path, **without the query string** and without
   scheme, host or port. `/api/v1/agent/heartbeat`.

   The path is signed so that a signature made for a heartbeat cannot be lifted
   onto a certificate request.

   The query string is **not** covered. No agent endpoint takes parameters in
   the query today; do not put anything security-relevant there, because nothing
   protects it.

   The core compares against the decoded path. Every agent route is literal
   ASCII, so percent-encoding does not arise — but if you invent a path where it
   does, sign the decoded form.

4. **`<unix-seconds>`** — the same integer as the `X-CertPilot-Timestamp`
   header, base-10, no leading zeros, no milliseconds. Signing a different
   value from the one in the header is the single most common way to produce a
   signature that will not verify.

5. **`<body hash>`** — SHA-256 of the **exact bytes of the request body**, hex,
   lowercase.

   Of the bytes you are about to send, not of a re-serialisation of the object
   you sent. If your HTTP client re-encodes JSON, hash after it has done so, or
   send a pre-encoded byte string.

   **An empty body hashes normally.** It is not skipped and the field is not
   omitted, so "no body" and "a body that happens to be empty" cannot be
   swapped:

   ```
   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
   ```

The body must be **at most 1 MiB**. The core has to buffer it whole before it
can check a signature over its hash, so the limit is what stops a caller making
it allocate before proving anything. Over that, `413`.

---

## 4. Signing

Ed25519 as in RFC 8032 — "pure" Ed25519, `PureEdDSA` with SHA-512 internally.
**Not** Ed25519ph, **not** Ed25519ctx. Sign the signing-string bytes directly;
do not pre-hash them yourself.

Ed25519 is deterministic: the same key over the same message always yields the
same 64 bytes. That has a consequence for retries — see §6.

Base64-encode the 64-byte signature with standard alphabet and padding, and put
it in `X-CertPilot-Signature`.

---

## 5. What the core checks, in order

The order is load-bearing and an implementer should know it, because it decides
what each failure means.

1. **All three headers present**, and the timestamp parses as an integer.
2. **Body read**, bounded at 1 MiB.
3. **Agent looked up** by `X-CertPilot-Agent`.
4. **Stored public key parsed.**
5. **Timestamp freshness** — `|now − timestamp| ≤ 300 s`. Five minutes, in
   either direction; a host whose clock is ahead is as common as one behind.
6. **Signature verified.**
7. **Agent status** — checked *after* the signature. This is deliberate: a
   revoked agent must not be distinguishable from an unknown one to anybody who
   can guess an id, or the endpoint becomes a way to enumerate the fleet. Only
   a caller who has proved it holds the private key is told it was revoked —
   which is exactly the caller who needs to know, so it can stop.
8. **Replay** — §6. Last, because a row written before the signature verifies
   would let anyone reachable fill the table with unsigned garbage.

---

## 6. Replay, and the retry trap

**Read this section even if you skim the rest.**

Steps 1–7 make a signature useless on any other method, path, timestamp or
body. They do **not**, on their own, stop the *identical* request being sent
twice inside the five-minute window. The core stops that separately, and the
mechanism has a consequence for your client.

**The signature is the nonce.** Ed25519 is deterministic, so two identical
requests carry identical signatures, and a signature is already unique to the
method, path, timestamp and body it covers. The core stores a hash of the
signature per agent until `timestamp + 300 s` and refuses a second request
carrying the same one. There is no nonce header and no protocol version for
this; it works with agents already deployed.

### Guarded by default, exempt by exception

Every agent endpoint is replay-guarded **except** these four:

```
/api/v1/agent/heartbeat
/api/v1/agent/inventory
/api/v1/agent/installations
/api/v1/agent/deployments/result
```

Those are idempotent reports; replaying one re-states something already true,
and refusing it would turn a recovered network blip into a failure.

The list is exemptions rather than opt-ins so that a route added tomorrow is
protected without anybody remembering to protect it. Assume any endpoint not on
that list is guarded, including ones added after this document.

`POST /api/v1/agent/certificates` is guarded, and it is why this exists:
replaying one captured off the wire gets a second certificate signed for the
same names — against the CA's rate limit, into the inventory, and for a public
CA into the CT logs. `POST /api/v1/agent/deployments/claim` leases work.
Neither is a report and neither changes nothing.

### The trap

> **On retry, re-sign with a fresh timestamp. Never re-send the same bytes.**

The obvious client retries by sending the buffered request again. Because
Ed25519 is deterministic, those bytes carry the *same signature*, and on a
guarded endpoint the core will refuse them as a replay — of your own earlier
attempt. Build the request again, with `now` as the timestamp, and sign again.

The one case this cannot help you with: two **genuinely distinct** requests
with identical bodies to the same path within the same second are
byte-identical, because the timestamp has one-second resolution. The core
cannot tell them apart and will refuse the second. If your agent can generate
those, put something varying in the body.

---

## 7. Keys

| | Encoding |
|:---|:---|
| Public | PKIX / SubjectPublicKeyInfo DER, PEM-wrapped as `PUBLIC KEY` |
| Private | PKCS#8 DER, PEM-wrapped as `PRIVATE KEY`. Never leaves the host |

PEM rather than raw base64 so that what is in the database, what the agent
prints, and what the API shows are the same inspectable thing.

**Key ID** — the first 16 hex characters of the SHA-256 of the **PKIX DER**
(not of the PEM, not of the raw 32-byte key). It is for humans: an operator
compares the line the agent printed on the host against the row in the API to
answer "is the thing enrolled under this name the machine I ran the command
on". It is never used to look a key up; a truncated hash is not an identifier.

---

## 8. Enrolment

`POST /api/v1/agent/enrol` is the one agent call that is **not** signed,
because the agent has no identity yet — this is the request that gives it one.
It is authenticated by a one-use enrolment token instead.

Generate the key pair first, locally. Send the public half. Keep the private
half on the host.

**Labels come from the enrolment token, not from the agent.** That is what makes
them worth trusting: a host cannot label itself into a grant somebody wrote for
a different tier. Do not expect to set your own.

---

## 9. What comes back

Every authentication failure is a flat **401** with one sentence and no detail:

```json
{ "error": "this request was not accepted as coming from an enrolled agent" }
```

Which of the checks failed goes to the core's log, where an operator can see it,
and not onto the wire, where it would tell a caller which one to work on next.
**You cannot debug your implementation from the response.** Use the vectors in
§11.

Three responses say more, because they need to:

| Status | `code` | Meaning |
|:---|:---|:---|
| 403 | `agent_revoked` | Stop permanently. Do not retry, do not back off — the credential is withdrawn. |
| 401 | `agent_replay` | The core has seen this exact request. Your retry did not re-sign; see §6. |
| 503 | — | The replay check was unavailable, so the request was refused rather than assumed fresh. Retry with a fresh signature. |

`agent_revoked` is distinct from a 403 about policy — "you may not have that
certificate" — and the two call for opposite responses: stop for good, or
report a problem somebody can fix. An agent that could not tell them apart shut
itself down over a missing grant. Check the `code`.

Accepted requests carry the core's own clock back, because drift is the
commonest cause of a signature that will not verify, and an agent that can see
the difference can say so instead of reporting "unauthorized" for ever.

---

## 10. Ways to build this wrong

Each of these produces a flat 401 that tells you nothing.

- [ ] Signing a different timestamp from the one in the header
- [ ] Milliseconds instead of seconds
- [ ] Lowercase method in the signing string
- [ ] URL-safe base64, or stripping the `==` padding
- [ ] Including the query string in the signed path, or the full URL
- [ ] Omitting the body-hash line when the body is empty, or hashing the string `"null"`
- [ ] Hashing the object rather than the bytes your client actually transmits
- [ ] A trailing newline after the body hash
- [ ] `\r\n` between fields
- [ ] Ed25519ph (pre-hashed) instead of pure Ed25519
- [ ] Re-sending buffered bytes on retry — §6, and this one returns `agent_replay`
- [ ] Sending the private key anywhere, ever

---

## 11. Test vectors

Ed25519 seed, 32 bytes, `00 01 02 … 1f`:

```
seed (hex)  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
public key  03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
key id      a050837d85070582
```

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=
-----END PUBLIC KEY-----
```

```
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f
-----END PRIVATE KEY-----
```

### Vector 1 — a body

```
method     POST
path       /api/v1/agent/heartbeat
timestamp  1767225600
body       {"status":"ok"}

body sha256     a29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288
signing string  "certpilot-agent-v1\nPOST\n/api/v1/agent/heartbeat\n1767225600\na29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288"
signature       iTjTV/pEPOdexLzQtUy7Fo2E2z6XbhI7STzuet0Bj1b6KGrVvVZW+NImAz03lJHvg+2OxYiyUVrInM7GiO1FBQ==
```

### Vector 2 — empty body

The one to check first, because skipping the hash for an empty body is the
easiest mistake to make and it verifies fine against a signer with the same bug.

```
method     POST
path       /api/v1/agent/certificates
timestamp  1767225600
body       (empty)

body sha256     e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
signing string  "certpilot-agent-v1\nPOST\n/api/v1/agent/certificates\n1767225600\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
signature       V76KKzQosvCLrvdpljSEipiqbFQL7mFmNH2P8P/K1ernzPOZHA+efr5Ex1CCAZNfHRRjkXmGwMjh6IcNldF5AQ==
```

### Vector 3 — method uppercased

Given `post`, the signing string must contain `POST`.

```
method     post
path       /api/v1/agent/inventory
timestamp  1767225600
body       {}

body sha256     44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a
signing string  "certpilot-agent-v1\nPOST\n/api/v1/agent/inventory\n1767225600\n44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
signature       /7Llzg+yT8gDnBo9pInvNARFhOCBTZwBzdT8VGeiFmUvVqR/s74Jrqjvi9Okj25xtiz/WXYibh5ckUnhZld4CA==
```

These are produced from the Go in this repository by `TestTheDocumentedVectorsStillHold`.
If a change here ever makes that test fail, the scheme has changed and it needs
a new name — `certpilot-agent-v2` — not a quiet edit to this file.

---

## 12. A reference implementation, in Python

Complete, and short enough to check by eye against §3.

```python
import base64, hashlib, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

SCHEME = "certpilot-agent-v1"

def load_private_key(pem: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem.encode(), password=None)

def signing_string(method: str, path: str, timestamp: int, body: bytes) -> bytes:
    return "\n".join([
        SCHEME,
        method.upper(),
        path,                                    # no query string
        str(timestamp),
        hashlib.sha256(body).hexdigest(),        # empty body included, not skipped
    ]).encode("utf-8")

def headers(agent_id: str, key: Ed25519PrivateKey,
            method: str, path: str, body: bytes) -> dict:
    # Called afresh for every attempt, including retries: re-sending a previous
    # signature is a replay, and guarded endpoints refuse it.
    ts = int(time.time())
    sig = key.sign(signing_string(method, path, ts, body))
    return {
        "X-CertPilot-Agent":     agent_id,
        "X-CertPilot-Timestamp": str(ts),
        "X-CertPilot-Signature": base64.b64encode(sig).decode(),
        "Content-Type":          "application/json",
    }
```

Check it against §11 before pointing it at a core:

```python
key = load_private_key(open("vector.key").read())
assert base64.b64encode(
    key.sign(signing_string("POST", "/api/v1/agent/certificates", 1767225600, b""))
).decode() == "V76KKzQosvCLrvdpljSEipiqbFQL7mFmNH2P8P/K1ernzPOZHA+efr5Ex1CCAZNfHRRjkXmGwMjh6IcNldF5AQ=="
```
