# Project Wiki

This is the long-form documentation for the project. While [README.md](README.md) covers orientation and quick start, the Wiki explains the *how* and *why* in depth.

## Table of Contents

- [Home](#home)
- [Architecture Overview](#architecture-overview)
- [Development Guide](#development-guide)
- [Coding Conventions](#coding-conventions)
- [Testing Strategy](#testing-strategy)
- [Release Process](#release-process)
- [Glossary](#glossary)
- [FAQ](#faq)

---

## Home

Welcome to the project Wiki. Use this document (or split it into separate Wiki pages as it grows) for:

- **Design documents** – why the system is shaped the way it is
- **Reference material** – module/package APIs, configuration options, data formats
- **Operational guides** – how to build, test, deploy, and debug

Keep each page focused; link between pages instead of duplicating content. Update this Wiki in the same pull request as any behavior change so docs never drift from code.

---

## Architecture Overview

> **Status:** To be filled in as the first modules land.

Recommended contents once code exists:

1. **System context** – a diagram showing the system and its external interactions (users, services, data sources).
2. **Component view** – major packages/modules under `src/` and their responsibilities.
3. **Data flow** – how data enters, is transformed, and leaves the system.
4. **Key design decisions** – short ADR-style entries:
   - Title, Status (Proposed/Accepted/Superseded), Context, Decision, Consequences.

### Example ADR template

```markdown
### ADR-0001: <Title>
- **Status:** Proposed
- **Date:** YYYY-MM-DD
- **Context:** What problem or force are we addressing?
- **Decision:** What did we decide to do?
- **Consequences:** Positive, negative, and trade-offs accepted.
```

---

## Development Guide

### Environment setup

Follow the installation steps in [README.md](README.md). Additionally:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt        # runtime dependencies
pip install -r requirements-dev.txt    # linters, formatters, test tools (when added)
```

### Running locally

Document concrete commands here once entry points exist, e.g.:

```bash
python -m <package> run --config config/dev.yaml
```

### Debugging

- Log locations / log levels and how to raise verbosity
- Common failure modes and their remedies

---

## Coding Conventions

- **Style:** Follow PEP 8 for Python; use an automated formatter (e.g., `black` or `ruff format`) enforced in CI.
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE_CASE` for constants.
- **Type hints:** Preferred on all public functions; consider adding `mypy` in CI.
- **Docstrings:** Google- or NumPy-style docstrings on public modules, classes, and functions.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).

---

## Testing Strategy

| Layer | Tooling (suggested) | Scope |
|-------|---------------------|-------|
| Unit tests | `pytest` | Individual functions/classes, no I/O |
| Integration tests | `pytest` + fixtures | Module interactions, temp files/dbs |
| End-to-end tests | TBD | Full workflows against a real deployment |

Guidelines:

- Every bug fix ships with a regression test.
- Aim for meaningful coverage of business logic rather than chasing a percentage.
- Tests live alongside source in a `tests/` tree mirroring `src/`.

---

## Release Process

1. All CI checks green on the main branch.
2. Bump version numbers (semver: MAJOR.MINOR.PATCH).
3. Update the changelog (`CHANGELOG.md`) with user-facing changes.
4. Tag the release (`vX.Y.Z`) and build artifacts.
5. Publish/deploy and verify in production/staging.
6. Announce to stakeholders.

---

## Glossary

| Term | Definition |
|------|------------|
| ADR | Architecture Decision Record – a short document capturing a key design decision. |
| Semver | Semantic Versioning – MAJOR.MINOR.PATCH versioning scheme. |
| CI | Continuous Integration – automated build/test pipeline. |

Add project-specific terms here as they are introduced.

---

## FAQ

**Q: Where should new documentation go — README or Wiki?**
A: Quick-start, overview, and "how to contribute" basics belong in the README. Deep dives, references, tutorials, and design records belong in the Wiki.

**Q: The Wiki and code disagree — which wins?**
A: The code is authoritative; fix the Wiki in the same change that touches behavior.

---

*Last reviewed: 2026-10-08. This page was seeded while the repository is still in its initial state; update each section as real content lands.*
