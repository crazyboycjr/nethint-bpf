# nethint-bpf

```
git submodule update --init --recursive
cargo r --bin nethint-user
sudo -E cargo r --bin nethint-user <interface>
```

using nix flakes
```
nix develop
cargo r --bin nethint-user
sudo -E cargo r --bin nethint-user <interface>
```
