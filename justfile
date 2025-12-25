alias r := run

iface := `find /sys/class/net -mindepth 1 -maxdepth 1 -lname '*virtual*' -prune -o -printf '%f\n'`
log_lvl := "debug"

run:
  RUST_LOG={{log_lvl}} cargo run --locked --config 'target."cfg(all())".runner="sudo -E"' -- --iface {{iface}} "$@"
