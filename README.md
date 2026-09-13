# certpilot-agent-sdk

The contract between a host and the [CertPilot](https://github.com/certpilot/certpilot)
core: the wire types, and the signing scheme that makes a request provably from
the agent it claims to be.

```
go get github.com/certpilot/certpilot-agent-sdk
```

Current release: **v0.1.0**. The CertPilot core and its agent both build against
it with no `replace` directive, which is the only real test of whether this is
published or merely copied.

## Why this is published

**An agent does not have to be *the* agent.** The Go binary CertPilot ships is
one implementation of this contract — it imports no protobuf and no gRPC; it is
an HTTP client with a signature. Somebody running a fleet of Windows servers, a
Kubernetes operator, or an embedded device that will never run a Go daemon
needs the contract, not the binary.

Until now that contract existed only as Go, behind a `replace` directive, in a
repository you would need commit access to.

| Package | |
|:---|:---|
| `agentauth` | the signing scheme: key generation, `SigningString`, `Sign`, `Verify`, key encoding |
| `agentapi` | the wire types both sides speak — inventory, installations |

One definition of those types rather than one per side. They cross a version
boundary wider than any other in this system: an agent installed on a host in
March is still running in December against a core upgraded four times. A field
that means one thing on one side and something else on the other is the failure
mode, and two copies of a struct is how it starts.

## [`SIGNING.md`](SIGNING.md) is the actual contract

Read it before writing an agent in another language. It gives the canonical
string byte by byte, the algorithm, the freshness window, the replay rule, the
error codes, **published test vectors**, and a complete Python implementation
short enough to check by eye.

It is written to be precise enough that a reader cannot accidentally build the
insecure version, because the core cannot help you find out: every
authentication failure is a flat `401` with one sentence and no detail, on
purpose, so that a caller cannot learn which check to work on next. **You
cannot debug an implementation from the responses.** Check it against the
vectors instead — `TestTheDocumentedVectorsStillHold` in this repository is
what keeps them true.

Three things in there that are easy to get wrong and expensive to get wrong:

- **An empty body is hashed, not skipped.** A signer with that bug verifies
  perfectly against itself and never against the core.
- **A retry must re-sign with a fresh timestamp.** Ed25519 is deterministic, so
  re-sending buffered bytes re-sends the signature, and guarded endpoints refuse
  it as a replay of your own earlier attempt.
- **`agent_revoked` and a policy `403` are different mornings.** One means stop
  for good; the other means report a problem somebody can fix. An agent that
  could not tell them apart shut itself down over a missing grant.

## What an agent is not

The core has **no route by which it can tell a host which files to write or
what command to run.** Installation specifications are read from a file on the
host; what travels upward is what the host was told to do and what happened
when it did. There is deliberately no wire type in `agentapi` for a command.

A core that could hand an agent a command to run would be a fleet-wide remote
execution channel wearing a certificate manager's clothes. Keep it that way in
whatever you build.

Likewise: **the host generates the key and sends only a request.** CertPilot
signs what an operator granted that host and never holds a private key it could
lose or be compelled to produce. And **labels come from the enrolment token,
not from the agent** — a host cannot label itself into a grant somebody wrote
for a different tier.

## Licence

Apache 2.0. See [LICENSE](LICENSE).
