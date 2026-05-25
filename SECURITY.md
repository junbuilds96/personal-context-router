# Security Policy

Personal Context Router is a local-first CLI. It does not run a hosted service
or send data over the network during normal operation.

## Supported Versions

The public repository is pre-1.0. Security fixes target the latest `main`
branch until versioned releases are established.

## Reporting

Use GitHub private vulnerability reporting if it is available for this
repository. If the issue is not sensitive, open a normal GitHub issue with a
minimal synthetic reproduction.

Do not include real secrets, private notes, customer data, or personal contact
details in reports, issues, tests, or screenshots.

## Scope

In scope:

- redaction bypasses for the documented built-in patterns
- unsafe artifact generation that copies redacted or unapproved content into a
  packet
- command behavior that contradicts the approval gate or diagnostic contract

Out of scope:

- claims that the project is a complete DLP system
- vulnerabilities in local tools outside this package
- reports requiring real private data to reproduce
