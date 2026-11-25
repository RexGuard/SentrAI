# SentrAI Gate

The standalone edition of SentrAI: a firewall for one Linux machine, with no account, no sign-in
and no panel. It drops flood traffic at the network card (eBPF/XDP) and never sends anything back
at the sender.

User guide: [docs/gate.md](../docs/gate.md) · Install: `curl -fsSL https://raw.githubusercontent.com/RexGuard/SentrAI/main/gate/install.sh | sudo bash`

## Layout

```
bpf/gate.bpf.c          the kernel programs: gate_ingress (XDP, the pipeline) and gate_egress (TC, takes notes)
bpf/gate.h              structs shared with the control tool
bpf/headers/            libbpf helper headers (BSD-2-Clause), so the build needs no kernel headers
internal/kern/          loads the programs, steps down on older kernels, reads and writes the maps
                        gate_bpfel.o / gate_bpfel.go are generated and committed: building needs only Go
internal/config/        settings file, profiles and levels, allow / block list files
internal/engine/        the running service: learned normal level, attack calls, ban upkeep, status file
internal/tui/           the live screen
cmd/sentrai-gate/       the command line
install.sh, uninstall.sh, sentrai-gate.service
```

## Build and test

```bash
make                 # ./sentrai-gate, needs Go 1.23+
sudo make test       # kernel tests load the real filter and feed it packets; they skip without root
make bpf             # only after editing bpf/: needs clang, rewrites internal/kern/gate_bpfel.*
```

The kernel tests use the kernel's own test hook (`BPF_PROG_TEST_RUN`), so they need no network
and no second machine.

## How the pieces talk

- The service (`sentrai-gate run`) owns the filter. If it stops, the kernel detaches the filter
  and traffic flows untouched.
- It pins its maps under `/sys/fs/bpf/sentrai-gate/`. The command line writes timed bans there
  directly, and edits the list files then signals the service (SIGHUP) for everything else.
- Every second the service writes `/run/sentrai-gate/status.json`. `status` and the live screen
  only read that file.

## Stepping down

`internal/kern/loader.go` tries the full pipeline first and sets two read-only constants in the
program before loading (`gate_level`, `gate_events`). The kernel removes the code a switched-off
stage would use, so an older kernel never has to accept it. Attach tries the driver mode, then
the general one. Every step taken is recorded and shown on the System page.

## Licence note

The kernel programs are dual BSD/GPL, as the kernel asks of programs that run inside it.
