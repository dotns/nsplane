# nsplane documentation

This page lists every document of the repository and the standard they follow: which class a
document belongs to, how it is written, and which documents a change has to update.

## Index

| Document | Content |
|---|---|
| [README](../README.md) | What nsplane is, the crates, how to depend on it and build it |
| [Usage guide](guide.md) ([中文](guide.zh-CN.md)) | Embedding nsplane, by deployment, with code |
| [Architecture](architecture.md) | Scope and principles, crate graph, data flow, threading, contracts, unsafe code, crypto, testing |
| [Reference](reference/) | One document per crate: the behavior of each component, defaults, errors, limits, costs |
| [Performance](performance.md) | How performance is measured and the current numbers |
| [Specs](specs/) | How a product maps its own model onto the generic APIs |
| [Examples](../examples/README.md) | The runnable example programs |
| [CHANGELOG](../CHANGELOG.md) | Changes per release |
| [Decisions](decisions/) | Architecture decision records (ADR) |
| [Plans](plan/index.md), [tasks](task/index.md), [project log](changelog.md) | Work in progress and its history |

## Classes

Every document belongs to one class.

| Class | Documents | Describes |
|---|---|---|
| Product | `README.md`, `examples/README.md`, `docs/*.md` (except `docs/changelog.md`), `docs/reference/`, `docs/specs/`, `CHANGELOG.md` | what the code on `main` does |
| Decision | `docs/decisions/` | why a lasting choice was made |
| Process | `docs/plan/`, `docs/task/`, `docs/changelog.md` | planned and finished work |

Code comments follow the rules of product documents.

## Writing rules

Product documents and code comments:

- State current behavior in the present tense: what a component does, its contract,
  defaults, limits, errors and costs.
- No plan, task, campaign or slice ids, no references into `docs/plan/` or `docs/task/`.
- No history: no dates, no "as before", "since 0.13", "in 0.14.2", "previously". What changed
  between releases belongs in `CHANGELOG.md`.
- No intentions: no "later", "for now", "will be removed", "planned", `TODO`. Open work is a
  task document. A deprecated item states its status and its replacement
  (`#[deprecated(note = ...)]` and one rustdoc line).
- Numbers from measurements appear only in `docs/performance.md`, each with its method; a new
  measurement replaces the old row.
- Product documents are business-agnostic like the code: consumer products are named only in
  `docs/specs/`.
- ADRs are cited by their slug (`2026-10-06-business-agnostic-scope`) or linked.

Rustdoc states behavior, contract, errors (`# Errors`), panics (`# Panics`) and costs. An inline
comment explains why the code is written the way it is, not what it will become.

Decision and process documents may contain dates, ids, history and plans.

## Templates

### Product document

```markdown
# <Title>

<One paragraph: what this document covers and for whom.>

## <Sections>
```

### Reference document (`docs/reference/<crate>.md`)

```markdown
# <crate>

<One paragraph: what the crate is for and which crates it builds on.>

## Public API
| Item | Role |

## Behavior
### <Component>

## Configuration and defaults
## Errors and drop reasons
## Limits and bounds
## Data-path cost
## Platform notes
## See also
```

Sections without content are left out; the order stays.

### Spec (`docs/specs/<name>.md`)

```markdown
# <Title>

- **Status**: Current
- **Applies to**: <crates>

<What a product maps onto which generic API.>
```

### ADR (`docs/decisions/YYYY-MM-DD-<slug>.md`)

```markdown
# ADR: <title>

- **Status**: Proposed | Accepted | Superseded by <ADR>
- **Date**: YYYY-MM-DD
- **Review**: <date or condition> | none

## Context
## Decision
## Consequences
## Status history
```

`Status history` lists later status changes, one line each, and is left out while there are
none.

Plans and tasks follow the PMA templates in `docs/plan/index.md` and `docs/task/index.md`.

## Delivery

A change updates its documents in the same commit:

| Change | Documents |
|---|---|
| Public API added or changed | rustdoc of the items; `docs/reference/<crate>.md`; `docs/guide.md` and `docs/guide.zh-CN.md` when usage changes; `CHANGELOG.md` `[Unreleased]` |
| Behavior change or bug fix | rustdoc where the contract changes; `docs/reference/<crate>.md`; `CHANGELOG.md` |
| Performance change | the row in `docs/performance.md`; `CHANGELOG.md` |
| New crate | `docs/reference/<crate>.md`; the crate tables in `README.md` and `docs/architecture.md` |
| Release | the `CHANGELOG.md` section; the `docs/changelog.md` entry |

Both guide languages change together and carry the same content.

## Checks

`just check` runs `scripts/check-docs.sh`:

- wording: the rules above, in product documents and in the comments of `crates/` and
  `examples/`; exceptions are listed with a reason in `scripts/check-docs-allow.txt`;
- links: relative links and their anchors resolve;
- coverage: every published crate has its reference document.

The complete programs in the usage guide compile and run as doctests of `nsplane-examples`;
fragments are marked `rust ignore`.
