# `make IFACE=xxx run`
IFACE ?= $(shell find /sys/class/net -mindepth 1 -maxdepth 1 -lname '*virtual*' -prune -o -printf '%f\n')
LOG_LVL ?= debug

# Capture extra args passed after target name
ARGS = $(filter-out $@,$(MAKECMDGOALS))

.PHONY: run r check-bpf-linker check-iface

r: run

check-bpf-linker:
	@command -v bpf-linker >/dev/null 2>&1 || { echo "bpf-linker not found, installing with cargo ..."; cargo install bpf-linker --locked; }

check-iface:
	@IFACE_COUNT=$$(echo "$(IFACE)" | wc -l); \
	if [ "$$IFACE_COUNT" -gt 1 ]; then \
		echo "Multiple network interfaces found:"; \
		echo "$(IFACE)"; \
		echo ""; \
		echo "Please specify interface with: make IFACE=<interface> run"; \
		exit 1; \
	fi

run: check-bpf-linker check-iface
	RUST_LOG=$(LOG_LVL) cargo run --locked --release --config 'target."cfg(all())".runner="sudo -E"' -- --iface $(IFACE) $(ARGS)

# Prevent make from treating extra args as targets
%:
	@:
