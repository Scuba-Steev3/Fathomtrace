SHELL := bash

LIBS := $(wildcard lib/fathomtrace/*.sh)
BASH_SOURCES := fathomtrace bash_simpleportscan.sh install.sh $(LIBS) tests/run.sh

.PHONY: test syntax lint format-check

test: syntax
	bash tests/run.sh

syntax:
	bash -n $(BASH_SOURCES)

lint:
	shellcheck --severity=warning --shell=bash $(BASH_SOURCES)

format-check:
	shfmt -d -i 4 -ci -sr $(LIBS) tests/run.sh install.sh bash_simpleportscan.sh
