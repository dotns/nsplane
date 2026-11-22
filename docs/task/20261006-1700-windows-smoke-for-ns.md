# 20261006-1700-windows-smoke-for-ns Windows TUN smoke scenario for ns (MT-3 addendum)

- **status**: completed (run here on the Windows 11 test VM, 2026-11-21; ns may repeat it on its own host)
- **priority**: P1
- **owner**: ns (requested by L1 7f5cstru)
- **createdAt**: 2026-10-06 17:00

## Description

QW (merged on main) changed `Tun::create_with`:
- An orphaned Wintun adapter (a ghost left by a killed process) is replaced.
- A live adapter of the same name is still refused under `exclusive(true)`.
- The MTU is set and read back on both IPv4 and IPv6.

This host cannot run Wintun, so ns's automated Windows smoke should confirm the changes with
these steps:

1. Start the service with `Tun::create_with("<name>",
   TunOptions::new().wintun_pin(pin).exclusive(true).mtu(1420))`. Expect `Ok` and
   `tun.mtu() == 1420`. `Get-NetIPInterface -InterfaceAlias <name>` shows NlMtu 1420 for IPv4
   and IPv6.
2. While it runs, start a second process with the same call. Expect `Err` that downcasts to
   `WintunError::AdapterExists`.
3. Kill the service hard (`taskkill /F /PID`). `Get-NetAdapter -IncludeHidden -Name <name>`
   shows Status "Not Present".
4. Restart the service with the same call. Expect `Ok`. The adapter is Up and present, its
   alias is exactly `<name>` (not `<name> 2`), MTU 1420 on both families, and traffic passes.
   On `WintunError::OrphanNotReplaced`, report the `assigned` alias and the
   `Get-PnpDevice` output.
5. Repeat steps 3-4 once more, then stop the service cleanly and confirm that the adapter is
   removed.
6. Optional: with IPv6 unbound on the adapter, step 1 still succeeds with IPv4 1420.

## Result (2026-11-21)

Run on the Windows 11 test VM with the `tun_node` example (`--exclusive`, MTU 1420, no
`wintun_pin`) against kernel WireGuard in a container.

1. Pass: adapter Up, NlMtu 1420 on IPv4 and IPv6, ping through the tunnel 0 % loss.
2. Pass: the second process fails with `AdapterExists` within 0.2 s; the first keeps running.
3. Differs from the expectation: after `taskkill /F` the adapter is not listed by
   `Get-NetAdapter -IncludeHidden` at all (no "Not Present" entry); `Get-PnpDevice` shows
   the Wintun device as `Unknown`, not present.
4. Pass, twice: exact alias, Up, MTU 1420 on both families, traffic passes.
5. Pass: a run that ends on its own (`--exit-after-checks`) leaves no adapter.
6. Not run.

Defect found and fixed: about 4 in 150 exclusive starts after a hard kill failed with
`AdapterExists` although no process held the adapter, for 30 s to 3.5 min. Wintun logged
`Removed orphaned adapter` and could not open the name, while the alias still converted to
an interface row with `OperStatus` Down. Such a row is now classified as a remnant and
replaced (`wintun::Existing::Remnant`). After the fix: 60 kill and exclusive restart cycles
all started with the exact alias, 34 of them through the replacement.
