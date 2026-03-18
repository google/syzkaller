/*
 * Verify PF struct sizes used in syzkaller dev_pf.txt descriptions.
 * Build on OpenBSD: make pf_struct_sizes
 * Run: ./pf_struct_sizes
 * Expected: all assertions pass with no output, exit 0.
 */
#include <net/if.h>
#include <net/pfvar.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#define CHECK_SIZE(type, expected)                                       \
	do {                                                             \
		if (sizeof(type) != (expected)) {                        \
			printf("FAIL: sizeof(%s) = %zu, expected %zu\n", \
			       #type, sizeof(type), (size_t)(expected)); \
			fail = 1;                                        \
		}                                                        \
	} while (0)

#define CHECK_OFFSET(type, field, expected)                                               \
	do {                                                                              \
		if (offsetof(type, field) != (expected)) {                                \
			printf("FAIL: offsetof(%s, %s) = %zu, expected %zu\n",            \
			       #type, #field, offsetof(type, field), (size_t)(expected)); \
			fail = 1;                                                         \
		}                                                                         \
	} while (0)

int main(void)
{
	int fail = 0;

	/* Building block structs */
	CHECK_SIZE(struct pf_addr, 16);
	CHECK_SIZE(struct pf_addr_wrap, 48);
	CHECK_SIZE(struct pf_rule_addr, 56);
	CHECK_SIZE(struct pf_state_cmp, 16);
	CHECK_SIZE(struct pfsync_state_scrub, 8);
	CHECK_SIZE(struct pfsync_state_peer, 32);
	CHECK_SIZE(struct pfsync_state_key, 40);
	CHECK_SIZE(struct pfsync_state, 264);

	/* Ioctl argument structs */
	CHECK_SIZE(struct pfioc_state, 264);
	CHECK_SIZE(struct pfioc_states, 16);
	CHECK_SIZE(struct pfioc_state_kill, 224);
	CHECK_SIZE(struct pf_status, 520);
	CHECK_SIZE(struct pfioc_iface, 40);
	CHECK_SIZE(struct pfioc_tm, 8);
	CHECK_SIZE(struct pfioc_limit, 8);
	CHECK_SIZE(struct pfr_table, 1064);
	CHECK_SIZE(struct pfr_addr, 52);
	CHECK_SIZE(struct pfioc_table, 1104);
	CHECK_SIZE(struct pfioc_trans_e, 1032);
	CHECK_SIZE(struct pfioc_trans, 16);
	CHECK_SIZE(struct pfioc_ruleset, 1092);
	CHECK_SIZE(struct pfioc_natlook, 80);
	CHECK_SIZE(struct pfioc_synflwats, 8);
	CHECK_SIZE(struct pf_queuespec, 320);
	CHECK_SIZE(struct pfioc_queue, 328);
	CHECK_SIZE(struct pf_queue_bwspec, 16);
	CHECK_SIZE(struct pf_queue_scspec, 40);
	CHECK_SIZE(struct pf_queue_fqspec, 16);
	CHECK_SIZE(struct pf_rule, 1360);
	CHECK_SIZE(struct pfioc_rule, 3424);

	/* Critical field offsets in pfioc_state_kill */
	CHECK_OFFSET(struct pfioc_state_kill, psk_pfcmp, 0);
	CHECK_OFFSET(struct pfioc_state_kill, psk_af, 16);
	CHECK_OFFSET(struct pfioc_state_kill, psk_proto, 20);
	CHECK_OFFSET(struct pfioc_state_kill, psk_src, 24);
	CHECK_OFFSET(struct pfioc_state_kill, psk_dst, 80);
	CHECK_OFFSET(struct pfioc_state_kill, psk_ifname, 136);
	CHECK_OFFSET(struct pfioc_state_kill, psk_label, 152);
	CHECK_OFFSET(struct pfioc_state_kill, psk_killed, 216);
	CHECK_OFFSET(struct pfioc_state_kill, psk_rdomain, 220);

	/* Critical field offsets in pfioc_rule */
	CHECK_OFFSET(struct pfioc_rule, action, 0);
	CHECK_OFFSET(struct pfioc_rule, ticket, 4);
	CHECK_OFFSET(struct pfioc_rule, nr, 8);
	CHECK_OFFSET(struct pfioc_rule, anchor, 12);
	CHECK_OFFSET(struct pfioc_rule, anchor_call, 1036);
	CHECK_OFFSET(struct pfioc_rule, rule, 2064);

	/* pf_addr_wrap field offsets */
	CHECK_OFFSET(struct pf_addr_wrap, v, 0);
	CHECK_OFFSET(struct pf_addr_wrap, p, 32);
	CHECK_OFFSET(struct pf_addr_wrap, type, 40);
	CHECK_OFFSET(struct pf_addr_wrap, iflags, 41);

	/* pfioc_natlook field offsets */
	CHECK_OFFSET(struct pfioc_natlook, saddr, 0);
	CHECK_OFFSET(struct pfioc_natlook, daddr, 16);
	CHECK_OFFSET(struct pfioc_natlook, rsaddr, 32);
	CHECK_OFFSET(struct pfioc_natlook, rdaddr, 48);
	CHECK_OFFSET(struct pfioc_natlook, rdomain, 64);
	CHECK_OFFSET(struct pfioc_natlook, sport, 68);
	CHECK_OFFSET(struct pfioc_natlook, af, 76);

	if (!fail)
		printf("All struct size/offset checks passed.\n");

	return fail;
}
