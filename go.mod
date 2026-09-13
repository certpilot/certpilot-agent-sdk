// The contract between a host agent and the CertPilot core.
//
// Separate from the gateway SDK because they share nothing: an agent speaks
// HTTP with a signature and never imports the provider proto. Two extension
// points that happened to live in one directory.
//
// SIGNING.md is the normative description of the signing scheme, written so an
// agent can be implemented without reading any of this Go.
module github.com/certpilot/certpilot-agent-sdk

go 1.26.6
