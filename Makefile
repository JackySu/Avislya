IFACE := $(shell find /sys/class/net -mindepth 1 -maxdepth 1 -lname '*virtual*' -prune -o -printf '%f\n')
LOG_LVL := debug

# Capture extra args passed after target name
ARGS = $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run r

r: run

run:
	RUST_LOG=$(LOG_LVL) cargo run --locked --config 'target."cfg(all())".runner="sudo -E"' -- --iface $(IFACE) $(ARGS)

# Prevent make from treating extra args as targets
%:
	@:
