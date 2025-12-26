alias r := run

# `just iface=xxx run`
iface := `find /sys/class/net -mindepth 1 -maxdepth 1 -lname '*virtual*' -prune -o -printf '%f\n'`
log_lvl := "debug"

[private]
check-bpf-linker:
  @command -v bpf-linker >/dev/null 2>&1 || { echo "bpf-linker not found, installing..."; cargo install bpf-linker --locked; }

[private]
check-iface:
  #!/usr/bin/env bash
  IFACE_COUNT=$(echo "{{iface}}" | wc -l)
  if [ "$IFACE_COUNT" -gt 1 ]; then
    echo "Multiple network interfaces found:"
    echo "{{iface}}"
    echo ""
    echo "Please specify interface with: just iface=<interface> run"
    exit 1
  fi

run: check-bpf-linker check-iface
  RUST_LOG={{log_lvl}} cargo run --locked --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface {{iface}} "$@"
