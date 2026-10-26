PYTHON ?= python3
ENGINE ?= auto

.PHONY: all pcaps test test-suricata test-yara clean

all: test

pcaps:
	$(PYTHON) tools/gen_pcaps.py

test-suricata: pcaps
	$(PYTHON) tests/run_suricata_tests.py --engine $(ENGINE)

test-yara:
	$(PYTHON) tests/run_yara_tests.py

test: test-suricata test-yara

clean:
	rm -rf build
