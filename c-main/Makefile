ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable.")
endif
PKTPROC_PMD ?= ixgbe
PKTPROC_RTE_LIBS = rte_eal rte_cmdline rte_timer rte_malloc rte_mempool rte_mbuf rte_ring ethdev rte_pmd_$(PKTPROC_PMD)

CFLAGS = -std=gnu99 -march=native -Wall -O2 -g -I$(RTE_SDK)/include -I../libpktproc/include
LDFLAGS = -L$(RTE_SDK)/lib -L../libpktproc/target/release -pthread -lrt -lnuma -lpktproc -Wl,--whole-archive -Wl,--start-group $(patsubst %,-l%,$(PKTPROC_RTE_LIBS)) -Wl,--end-group -Wl,--no-whole-archive -ldl

.PHONY: clean

pktproc: main.c
	gcc $(CFLAGS) main.c -o pktproc $(LDFLAGS)

clean:
	rm pktproc
