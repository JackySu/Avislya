# avislya

Filter out polluted DNS packets by *GFW* 

## Prerequisites

1. Linux
2. install bpf-linker: `cargo install bpf-linker --locked`

## Build & Run

If you prefer to use `justfile`, then

```shell
just r
```

Or use Makefile

```shell
make
```

Build scripts are used automatically to build the eBPF program and include it.

## License

With the exception of eBPF code, avislya is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
