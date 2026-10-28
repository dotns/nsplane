# 20261028-0615-remove-transparent-admission Remove the deprecated TransparentConfig::admission

- **status**: in_progress
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
