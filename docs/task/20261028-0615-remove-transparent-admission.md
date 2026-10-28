# 20261028-0615-remove-transparent-admission Remove the deprecated TransparentConfig::admission

- **status**: completed (on `release/0.21.0` 2026-10-28; ships in 0.21.0, not yet tagged)
- **priority**: P2
- **owner**: pdev (oitcozuh)
- **createdAt**: 2026-10-28 06:15
- **plan**: 20261027-0433-post-freeze-schedule

## Description

`nsplane-netstack` `TransparentConfig::admission` is deprecated since 0.20.0 (release B),
replaced by `NetStackConfig::admission`, which applies to every stack; a transparent stack
honoured the old field while the top-level one was `Admission::Immediate`. Plan
`20261027-0433-post-freeze-schedule` schedules its removal for 0.21.0; the owner confirmed it
on 2026-10-28.

## Acceptance

- The field and its fallback in `Settings::new` are gone; the admission normalisation keeps
  its test.
- In-repo users set `NetStackConfig::admission`.
- Reference and CHANGELOG `[0.21.0]` `#### Breaking` with a migration example.

## Dependencies

- **blocked by**: (none)
- **blocks**: (none)

## Notes

- Removed on `feat/0.21.0-m3-removals`: the field, its default, the fallback in
  `Settings::new`. `admission_is_top_level_first_then_transparent` became
  `admission_is_normalised` (with and without a transparent config, the 24 h timeout clamp);
  `stack/tests/pending.rs` and `stack/tests/events.rs` set `NetStackConfig::admission`.
- `cargo semver-checks` against v0.20.2: `struct_pub_field_missing` for
  `TransparentConfig::admission`, nothing else in `nsplane-netstack`.
