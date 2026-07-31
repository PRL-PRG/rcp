include common.mk

.PHONY: all
all: install

.PHONY: install
BEAR := $(shell command -v bear 2>/dev/null)
BEAR := $(if $(BEAR),$(BEAR) --)

install:
	$(BEAR) $(R) CMD INSTALL .

.PHONY: clean
clean:
	$(MAKE) -C src -f Makevars clean
	rm -f compile_commands.json

.PHONY: test
test: install
	$(MAKE) -C tests test

.PHONY: run
run: install
	$(R)

.PHONY: debug
debug: install
	RCP_GDB_JIT=1 RCP_DUMP_DIR=/tmp $(R) -d gdb

.PHONY: format
format:
	find src -type f \( -name "*.c" -o -name "*.h" -o -name "*.cpp" \) -exec clang-format -i {} +

BENCH_ITER ?= 15
BENCH_PARALLEL ?= 1
BENCH_OUT_DIR ?=

.PHONY: benchmark
benchmark:
	@$(call ensure_microbenchmark_installed)
	@RSH_HOME=$(RSH_HOME) R_HOME=$(R_HOME) ./inst/benchmarks/run-benchmarks.sh \
		--runs $(BENCH_ITER) --parallel $(BENCH_PARALLEL) \
		$(if $(BENCH_OUT_DIR),--output $(BENCH_OUT_DIR))

# Build RCP with per-stencil profiling and export the counters for the whole
# benchmark suite as CSV. A clean rebuild is required because toggling
# PROFILE_STENCILS does not, on its own, retrigger compilation of unchanged
# sources. RUNS controls how many times each benchmark is executed (default 1);
# FILTER restricts to benchmarks whose filename contains the substring;
# PROFILE_OUT_DIR is where the CSVs land.
RUNS ?= 1
PROFILE_OUT_DIR ?= profile-results
FILTER ?=

.PHONY: profile
profile:
	$(MAKE) clean
	PROFILE_STENCILS=1 $(MAKE) install
	RSH_HOME=$(RSH_HOME) R_HOME=$(R_HOME) ./inst/benchmarks/run-profile.sh \
		--runs $(RUNS) --output $(PROFILE_OUT_DIR) \
		$(if $(FILTER),--filter $(FILTER))
