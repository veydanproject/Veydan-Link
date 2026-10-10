# VLink: the bridge, and what a client needs to use one.

.PHONY: build test check check-targets release release-all image third-party clean

SHELL := /bin/bash
ENV := source scripts/env.sh &&

# Debug build.
build:
	@$(ENV) cargo build

test:
	@$(ENV) cargo test

check:
	@$(ENV) cargo clippy --all-targets -- -D warnings

# The client library and the bridge build for every system they are meant for.
check-targets:
	@bash scripts/check-targets.sh

# The bridge as a static Linux binary in dist/.
release:
	@bash scripts/build-release.sh

# The bridge for Linux, x86_64 and aarch64, in dist/all/.
release-all:
	@bash scripts/build-all.sh

# The bridge as a docker image.
IMAGE ?= rookbeam/vlink
image: release
	@docker build -q -t $(IMAGE):$$(cut -d- -f1 dist/RELEASE) -t $(IMAGE):latest -f deploy/Dockerfile . >/dev/null
	@echo ">> $(IMAGE):$$(cut -d- -f1 dist/RELEASE)"

# THIRD-PARTY-LICENSES.md from Cargo.lock: run it after the lock changes.
third-party:
	@$(ENV) node scripts/third-party.mjs

clean:
	@rm -rf target dist
