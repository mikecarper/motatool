# motatool — dev tasks.
#
# The tool itself is pure Rust (`cargo build`) — including both delta encoders (`build --base`), which need
# NO detools/Python at runtime. detools is only the test ORACLE: the delta tests decode our patches with the
# real detools decoder to prove byte-exact apply-equivalence. `dev-setup` builds a local venv with detools
# from the third_party/detools submodule; the tests find it automatically (and skip cleanly without it).

PY ?= python3
VENV := .venv

.PHONY: build test dev-setup sync-targets check-targets clean-venv

build:
	cargo build --release

# One-time (or after bumping the submodule): fetch the pinned detools + its nested HDiffPatch and install
# it into a local venv. Requires a C toolchain (detools has C/C++ extension modules).
dev-setup:
	git submodule update --init --recursive
	$(PY) -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install ./third_party/detools
	@$(VENV)/bin/python scripts/detools_shim.py --detools-version | sed 's/^/detools ready: /'

# Full suite. Delta tests auto-skip if the detools venv isn't set up; run `make dev-setup` first to
# exercise them (they assert apply-equivalence against the real detools decoder).
test:
	cargo test

# Keep the human-readable OTA target labels synchronized with a sibling MeshCore checkout.
sync-targets:
	$(PY) scripts/sync_meshcore_targets.py

check-targets:
	$(PY) scripts/sync_meshcore_targets.py --check

clean-venv:
	rm -rf $(VENV)
