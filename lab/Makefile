LAB_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
PROBE := framework/probe

.PHONY: all build-probe scenarios test scenario-% replay-test

all: build-probe

build-probe:
	cd $(LAB_DIR)$(PROBE) && make linux-arm64 linux-amd64 darwin

# run a single scenario end-to-end (container + capture + probe)
scenario-%:
	bash $(LAB_DIR)framework/harness/run_scenario.sh $*

# run all scenarios, then validate alerts against the golden expectations
test: build-probe
	bash $(LAB_DIR)framework/harness/run_scenario.sh behinder
	bash $(LAB_DIR)framework/harness/run_scenario.sh normal
	bash $(LAB_DIR)framework/harness/run_scenario.sh ligolo
	python3 $(LAB_DIR)test/test_runner.py

# offline regression: replay captured pcaps through the probe rules
replay-test:
	cd $(LAB_DIR)$(PROBE) && \
	  ./behinder-probe-darwin -r ../../out/cap_behinder.pcap -json -ja3=false -scenario behinder 2>/dev/null | python3 -c "import sys,json,collections; print('behinder:', dict(collections.Counter(json.loads(l)['event'] for l in sys.stdin)))"; \
	  ./behinder-probe-darwin -r ../../out/cap_normal.pcap -json -ja3=false -scenario behinder,ligolo 2>/dev/null | python3 -c "import sys,json,collections; print('normal:', dict(collections.Counter(json.loads(l)['event'] for l in sys.stdin)))"; \
	  ./behinder-probe-darwin -r ../../out/cap_ligolo.pcap -json -ja3=false -scenario ligolo 2>/dev/null | python3 -c "import sys,json,collections; print('ligolo:', dict(collections.Counter(json.loads(l)['event'] for l in sys.stdin)))"
