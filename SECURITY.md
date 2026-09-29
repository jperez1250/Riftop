# Security Policy

## Supported Versions

Riftop is a **vibe-coded project** (an AI-assisted Rust rewrite of `iftop`). We iterate fast and fix bugs directly on the default branch. We do not maintain enterprise LTS releases.

| Version | Supported | Notes |
| ------- | --------- | ----- |
| `main` / `master` | :white_check_mark: | The latest commit is the only supported version. |
| Tagged Releases | :x: | Always pull latest `main` first to check if a bug was already patched. |

---

## Reporting a Vulnerability

Because this repo was built on pure vibes, AI assistance, and rapid prompt-driven coding, edge cases, logic bugs, or unhandled raw packet edge-cases *will* happen—especially around FFI/C bindings (`libpcap`) and root privileges.

### How to Submit Security Concerns

Depending on how bad the vibe is:

1. **Submit a PR (Preferred Vibe):** If you spot an issue in the code (e.g., an unhandled `unsafe` block, panic on malformed packet, or privilege leak), the fastest way to fix it is opening a **Pull Request**.
2. **Private Advisory:** If you found a critical privilege escalation or packet-of-death issue and want to report it privately, use [GitHub Private Vulnerability Reporting](https://github.com/jperez1250/Riftop/security/advisories/new).
3. **GitHub Issue:** For minor security concerns, memory leaks, or weird LLM-generated logic, open a standard **GitHub Issue** tagged with `security` or `vibe-check`.

### What to Include

- A quick explanation of what broke or went wrong.
- A minimal `.pcap` trace or steps to reproduce the panic/vulnerability.
- If an LLM wrote the buggy code, feel free to include the prompt or fix that solves it!

---

## Vibe Coding Security Disclaimer

* **AI-Generated Code:** Significant portions of this codebase were refactored or generated using LLMs. While Rust prevents most memory corruption bugs by design, logic errors or unsafe C-FFI behavior can still exist.
* **Elevated Privileges:** Riftop runs with raw socket permissions (`CAP_NET_RAW` or `sudo`). Always review code before running network sniffers as root.
* **Response SLAs:** This is a passion side-project. Security reports and fixes are handled on a best-effort, casual basis—no formal SLAs, just good vibes and git pushes.
