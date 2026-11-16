# Security policy

Guard Dog watches setups that hold people's money and identity, so we take reports about Guard Dog itself very seriously.

## Reporting a vulnerability in Guard Dog

Please **do not** open a public issue. Use GitHub's private vulnerability reporting on this repository: the **Security** tab, then **Report a vulnerability**.

Please include what you found, how to reproduce it, and what an attacker could do with it. We will acknowledge the report within 7 days, keep you updated, and credit you in the advisory unless you prefer otherwise.

## In scope

- Guard Dog's code in this repository, including its web UI and its handling of untrusted input (prompt injection, terminal or HTML injection).
- Guard Dog's release files and their signatures, once releases exist.
- The advisory feed format and Guard Dog's verification of signed advisories, once they exist.

## Out of scope

- Vulnerabilities in the software Guard Dog *monitors* (Bitcoin Core, Lightning implementations, relays, mints, platforms). Report those to their maintainers' security contacts. A private heads-up to us is welcome so the advisory feed can cover them once they're public.
- The clickable mock-up in `mockups/`, which is a static design prototype with sample data.

## Good-faith research

We will not take legal action against good-faith security research that follows this policy, avoids harming users or their funds, and gives us reasonable time to fix the problem before anything is disclosed.

## Current status

Guard Dog is pre-alpha and has no releases yet.
