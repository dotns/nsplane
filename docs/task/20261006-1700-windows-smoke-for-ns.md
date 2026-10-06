# 20261006-1700-windows-smoke-for-ns Windows TUN smoke scenario for ns (MT-3 addendum)

- **status**: pending (run by ns on a real Windows host; open item #5)
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
