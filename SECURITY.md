# Security policy

Tornect shares a computer's screen and takes remote input. It is pre-alpha, and no one has
audited it yet. If you find a way around one of its protections, please tell us privately first.

## Reporting a vulnerability

- Report it through GitHub's private vulnerability reporting: on
  <https://github.com/Mxrider007/Tornect>, open the **Security** tab and choose
  **Report a vulnerability**
  (<https://github.com/Mxrider007/Tornect/security/advisories/new>). Only you and the
  maintainers see the report.
- If GitHub does not offer that button, open an issue that asks for a private contact and holds no
  details of the problem.
- Please do not put details in a public issue, pull request or discussion before a fix is out.
- Helpful to include: the commit or release, the operating system, what an attacker needs (a
  network position, a paired device, an account on the host, someone at the screen), the steps
  to reproduce, and what they achieve.

The project is run by volunteers and promises no response time. The fix and an advisory are
published together, crediting you unless you ask not to be named. Fixes go to `main`; there
are no maintained release branches.

## In scope

The code in this repository and the release zips built from it with `cargo xtask dist`, in
particular:

- identities, pairing and its code comparison, and the keys pinned at pairing;
- the consent question, the sharing banner and indicator, Stop and the panic key;
- unattended access: grants, the OPAQUE password check, the wrong-password lock, the block
  window, the local control channel and the re-authentication before a change;
- the signaling and media protocols and their parsers, the encrypted stores, `sessions.log`;
- capture and input injection (what a viewer can see or do beyond what was granted);
- the release tooling's checks (`xtask`: the lyrebird signature and SHA-256 pins, the build
  record).

The design these protect is in [`docs/PLAN.md`](docs/PLAN.md) §B.6 and §B.8.

## Out of scope

- Weaknesses of Tor itself, of Arti, of lyrebird or of another dependency, with no
  Tornect-specific part: report them upstream (and tell us if Tornect must react).
- Attacks that need administrator or root rights, or the owner's own account, on the computer
  being attacked; a person at the host who accepts a session on purpose.
- The plain IP address a peer learns in a mode that sends media directly, which the design
  documents (no such mode is built yet).

## No bug bounty

There is no bug bounty: reports cannot be paid for.
