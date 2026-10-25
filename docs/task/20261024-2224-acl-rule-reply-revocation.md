# 20261024-2224-acl-rule-reply-revocation Revoke reply allowances of rule-accepted flows when their authority is gone

- **status**: completed
- **priority**: P1
- **owner**: roy/issue-8
- **createdAt**: 2026-10-24 22:24
- **plan**: 20261024-2224-acl-rule-reply-revocation

## Description

GitHub issue #8. With `stateful_replies` on, a reply allowance recorded for an inbound flow
accepted by an ordinary rule (default rules or a namespace rule) has no dependency, so it
survives a policy replacement or a change of the peer's labels: the old five-tuple keeps
passing through the reply table while new flows are denied. Grant and pinhole allowances are
already revoked.

Reproduced on main 1094adf with a filter unit test (peer `A` in a namespace accepting TCP 22
to the local node, local node answers, then the namespace is replaced by one without accept
rules, or `A`'s labels change):

| Case | old tuple after the change | new tuple |
|---|---|---|
| outbound unrestricted | Accept | Drop |
| outbound restricted to replies | Accept | Drop |
| peer labels changed | Accept | Drop |
| control: no response sent | Drop | Drop |
| control: `stateful_replies` off | Drop | Drop |

Acceptance criteria:

- After a policy or identity change, a packet is not accepted only because of an allowance
  recorded under an inbound authority that no longer accepts the flow.
- New unauthorized flows are denied (unchanged).
- Flows still accepted under the new policy, and flows the local node opened, keep working.
- No filter rebuild, address change or key change is required.

## ActiveForm

Revoking reply allowances of rule-accepted flows

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

(none)

- complete: Implemented per plan 20261024-2224-acl-rule-reply-revocation; nsplane-acl suite incl. differential tests, workspace clippy/test, docs checks passed. Bench A/B recorded in docs/changelog.md. Not yet committed.
