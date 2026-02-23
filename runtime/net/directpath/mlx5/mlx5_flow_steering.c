#include <base/log.h>
#include <base/time.h>
#include <runtime/sync.h>
#include <runtime/timer.h>
#include <runtime/thread.h>

#ifdef DIRECTPATH

#include <endian.h>
#include <string.h>

#include "mlx5.h"
#include "mlx5_ifc.h"

/* Interval for printing flow counters (in microseconds) */
#define FLOW_COUNTER_PRINT_INTERVAL_US (5 * ONE_SECOND)

/* Debug flag for runtime flow steering - set to 1 to enable debug prints */
#ifndef RT_FS_DEBUG
#define RT_FS_DEBUG 1
#endif

#if RT_FS_DEBUG
#define RT_FS_DBG(fmt, ...) log_info("[RT_FS_DBG] " fmt, ##__VA_ARGS__)
#else
#define RT_FS_DBG(fmt, ...) do { } while (0)
#endif

#define PORT_MATCH_BITS 10
#define PORT_MASK ((1 << PORT_MATCH_BITS) - 1)

/*
 * Flow counter support for debugging/statistics
 */
struct flow_counter {
	struct mlx5dv_devx_obj		*devx_obj;
	struct mlx5dv_dr_action		*action;
	uint32_t			id;
	const char			*name;
};

/* Counters for each level of the flow steering hierarchy */
static struct flow_counter	cnt_root_tcp;
static struct flow_counter	cnt_catchall;
static struct flow_counter	cnt_root_udp;
static struct flow_counter	cnt_last_level_fgs[NCPU];

static struct mlx5dv_dr_domain		*dmn;
static DEFINE_SPINLOCK(direct_rule_lock);
static DEFINE_BITMAP(tcp_listen_ports, 65536);
static DEFINE_BITMAP(udp_listen_ports, 65536);

struct tbl {
	struct mlx5dv_dr_table		*tbl;
	struct mlx5dv_dr_matcher		*default_egress_match;
	struct mlx5dv_dr_rule		*default_egress_rule;

	/* action that directs packets to this table */
	struct mlx5dv_dr_action		*ingress_action;
};

struct port_matcher_tbl {
	struct tbl		tbl;
	struct mlx5dv_dr_matcher		*match;
	unsigned int		port_no_bits;
	uint8_t ipproto;
	bool use_dst;
	size_t match_bit_off;
	size_t match_bit_sz;
	struct mlx5dv_dr_rule		*rules[];
};


/* level 0 flow table (root) */
static struct mlx5dv_dr_table		*root_tbl;
static struct mlx5dv_dr_matcher		*match_ip_and_tport;
static struct mlx5dv_dr_rule		*root_tcp_rule;
static struct mlx5dv_dr_rule		*root_udp_rule;

/* level 1 flow tables */
static struct tbl		tcp_tbl;
static struct tbl		udp_tbl;

static struct mlx5dv_dr_matcher		*udp_tbl_dport_match;
static struct mlx5dv_dr_matcher		*tcp_tbl_dport_match;

/* level 2 flow tables */
static struct port_matcher_tbl		*tcp_dport_tbl;
static struct port_matcher_tbl		*tcp_sport_tbl;
static struct port_matcher_tbl		*udp_dport_tbl;
static struct port_matcher_tbl		*udp_sport_tbl;

/* last level flow groups */
struct last_level_fg {
	struct tbl		tbl;
	unsigned int	qp_assignment;
};
static struct last_level_fg	last_level_fgs[NCPU];
static struct mlx5dv_dr_action		*fg_fwd_action[NCPU];

static union match empty_match = {
	.size = sizeof(empty_match.buf)
};

enum dr_matcher_criteria {
	DR_MATCHER_CRITERIA_EMPTY		= 0,
	DR_MATCHER_CRITERIA_OUTER		= 1 << 0,
};

/*
 * Flow counter allocation and query functions
 */
static int alloc_flow_counter(struct flow_counter *cnt, const char *name)
{
	/* DevX buffers must be 64 bytes minimum and 8-byte aligned */
	uint32_t in[16] __attribute__((aligned(8))) = {0};
	uint32_t out[16] __attribute__((aligned(8))) = {0};

	/* Set opcode: MLX5_CMD_OP_ALLOC_FLOW_COUNTER (0x939)
	 * The opcode goes in bits [31:16] of the first dword */
	in[0] = htobe32(MLX5_CMD_OP_ALLOC_FLOW_COUNTER << 16);

	cnt->devx_obj = mlx5dv_devx_obj_create(context, in, sizeof(in), out, sizeof(out));
	if (!cnt->devx_obj) {
		log_err("alloc_flow_counter(%s): devx_obj_create failed, errno=%d", name, errno);
		return -errno;
	}

	/* Extract counter ID from output (dword 2, bits [31:0]) */
	cnt->id = be32toh(out[2]);
	cnt->name = name;

	/* Create the DR action for this counter */
	cnt->action = mlx5dv_dr_action_create_flow_counter(cnt->devx_obj, 0);
	if (!cnt->action) {
		log_err("alloc_flow_counter(%s): action_create failed, errno=%d", name, errno);
		mlx5dv_devx_obj_destroy(cnt->devx_obj);
		return -errno;
	}

	RT_FS_DBG("alloc_flow_counter(%s): id=%u, action=%p", name, cnt->id, cnt->action);
	return 0;
}

static int query_flow_counter(struct flow_counter *cnt, uint64_t *packets, uint64_t *bytes)
{
	/*
	 * Query flow counter using DEVX command interface.
	 *
	 * Input layout (query_flow_counter_in):
	 *   dw0: opcode[31:16] | reserved[15:0]
	 *   dw1: reserved[31:16] | op_mod[15:0]
	 *   dw2: reserved (mkey in bulk mode)
	 *   dw3: flow_counter_id
	 *   dw4-7: address (bulk mode), clear, num_of_counters
	 *
	 * Output layout (query_flow_counter_out):
	 *   dw0: status[31:24] | reserved[23:0]
	 *   dw1: syndrome
	 *   dw2-3: reserved (0x40 bits)
	 *   dw4-5: packets (64 bits)
	 *   dw6-7: octets (64 bits)
	 *
	 * Buffers must be 64 bytes minimum and 8-byte aligned for DevX.
	 */
	uint32_t in[16] __attribute__((aligned(8))) = {0};
	uint32_t out[16] __attribute__((aligned(8))) = {0};
	int ret;

	if (!cnt->devx_obj)
		return -EINVAL;

	/*
	 * Per mlx5_ifc_query_flow_counter_in_bits:
	 *   dw0: opcode[31:16] | uid[15:0]
	 *   dw1: reserved[31:16] | op_mod[15:0]
	 *   dw2-5: reserved (0x80 bits = 4 dwords)
	 *   dw6: clear[31] | reserved[30:16] | num_of_counters[15:0]
	 *   dw7: flow_counter_id[31:0]
	 */
	in[0] = htobe32(MLX5_CMD_OP_QUERY_FLOW_COUNTER << 16);
    // DEVX_SET(query_flow_counter_in, in, num_of_counters, 1); 
	in[7] = htobe32(cnt->id);  /* flow_counter_id at offset 0xe0 */

	ret = mlx5dv_devx_obj_query(cnt->devx_obj, in, sizeof(in), out, sizeof(out));

	if (ret) {
		log_warn_ratelimited("query_flow_counter(%s): query failed ret=%d errno=%d",
		                      cnt->name, ret, errno);
		return -errno;
	}

	/* Check status in output dw0 bits [31:24] */
	uint8_t status = (be32toh(out[0]) >> 24) & 0xFF;
	if (status) {
        uint32_t syndrome = be32toh(out[1]); // Syndrome is in DW1
		log_warn_ratelimited("query_flow_counter(%s): cmd failed status=0x%x, syndrome=%d",
		                      cnt->name, status, syndrome);
		return -EIO;
	}

	/*
	 * Extract counters from output:
	 * - packets at dw4-5 (byte offset 0x10, after 0x40 bits of reserved at 0x40)
	 * - octets at dw6-7
	 */
	*packets = ((uint64_t)be32toh(out[4]) << 32) | be32toh(out[5]);
	*bytes = ((uint64_t)be32toh(out[6]) << 32) | be32toh(out[7]);

	return 0;
}

static int mlx5_tbl_init(struct tbl *tbl, int level, struct mlx5dv_dr_action *default_egress)
{
	struct mlx5dv_dr_action *action[1] = {default_egress};

	tbl->tbl = mlx5dv_dr_table_create(dmn, level);
	if (!tbl->tbl)
		return -errno;

	tbl->default_egress_match = mlx5dv_dr_matcher_create(tbl->tbl, 2, DR_MATCHER_CRITERIA_EMPTY, &empty_match.params);
	if (!tbl->default_egress_match)
		return -errno;

	tbl->ingress_action = mlx5dv_dr_action_create_dest_table(tbl->tbl);
	if (!tbl->ingress_action)
		return -errno;

	tbl->default_egress_rule = mlx5dv_dr_rule_create(
			  tbl->default_egress_match, &empty_match.params, 1, action);
	if (!tbl->default_egress_rule)
		return -errno;

	return 0;
}

static int mlx5_tbl_init_with_counter(struct tbl *tbl, int level,
                                       struct mlx5dv_dr_action *default_egress,
                                       struct flow_counter *cnt)
{
	struct mlx5dv_dr_action *actions[2];

	tbl->tbl = mlx5dv_dr_table_create(dmn, level);
	if (!tbl->tbl)
		return -errno;

	tbl->default_egress_match = mlx5dv_dr_matcher_create(tbl->tbl, 2, DR_MATCHER_CRITERIA_EMPTY, &empty_match.params);
	if (!tbl->default_egress_match)
		return -errno;

	tbl->ingress_action = mlx5dv_dr_action_create_dest_table(tbl->tbl);
	if (!tbl->ingress_action)
		return -errno;

	/* Include counter action before the destination action */
	actions[0] = cnt->action;
	actions[1] = default_egress;
	tbl->default_egress_rule = mlx5dv_dr_rule_create(
			  tbl->default_egress_match, &empty_match.params, 2, actions);
	if (!tbl->default_egress_rule)
		return -errno;

	return 0;
}

static struct port_matcher_tbl *alloc_port_matcher(uint8_t ipproto,
		      bool use_dst, unsigned int port_bits)
{
	int i, ret, pos = 0;
	union match mask = {0};
	struct port_matcher_tbl *t;
	struct mlx5dv_dr_action *action[1];
	unsigned int nrules = 1 << port_bits;

	t = calloc(1, sizeof(*t) + nrules * sizeof(struct mlx5dv_dr_rule *));
	if (!t)
		return NULL;

	t->port_no_bits = port_bits;
	t->ipproto = ipproto;
	t->use_dst = use_dst;

	ret = mlx5_tbl_init(&t->tbl, 2, last_level_fgs[0].tbl.ingress_action);
	if (ret)
		return NULL;

	if (ipproto == IPPROTO_TCP && use_dst) {
		t->match_bit_off = __devx_bit_off(fte_match_param, outer_headers.tcp_dport);
		t->match_bit_sz = __devx_bit_sz(fte_match_param, outer_headers.tcp_dport);
	} else if (ipproto == IPPROTO_TCP && !use_dst) {
		t->match_bit_off = __devx_bit_off(fte_match_param, outer_headers.tcp_sport);
		t->match_bit_sz = __devx_bit_sz(fte_match_param, outer_headers.tcp_sport);
	} else if (ipproto == IPPROTO_UDP && use_dst) {
		t->match_bit_off = __devx_bit_off(fte_match_param, outer_headers.udp_dport);
		t->match_bit_sz = __devx_bit_sz(fte_match_param, outer_headers.udp_dport);
	} else if (ipproto == IPPROTO_UDP && !use_dst) {
		t->match_bit_off = __devx_bit_off(fte_match_param, outer_headers.udp_sport);
		t->match_bit_sz = __devx_bit_sz(fte_match_param, outer_headers.udp_sport);
	} else {
		BUG();
	}

	mask.size = DEVX_ST_SZ_BYTES(fte_match_param);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_version, 4);
	_devx_set(mask.buf, __devx_mask(port_bits), t->match_bit_off, t->match_bit_sz);

	t->match = mlx5dv_dr_matcher_create(t->tbl.tbl, 0,
			      DR_MATCHER_CRITERIA_OUTER, &mask.params);
	if (!t->match)
		return NULL;

	for (i = 0; i < nrules; i++) {
		_devx_set(mask.buf, i, t->match_bit_off, t->match_bit_sz);
		action[0] = last_level_fgs[pos++ % maxks].tbl.ingress_action;
		t->rules[i] = mlx5dv_dr_rule_create(t->match, &mask.params, 1, action);
		if (!t->rules[i])
				return NULL;
	}

	return t;
}

static int mlx5_init_fg_tables(void)
{
	int i, ret;
	char name[32];

	for (i = 0; i < maxks; i++) {
		/* Allocate counter for this flow group */
		snprintf(name, sizeof(name), "fg[%d]", i);
		ret = alloc_flow_counter(&cnt_last_level_fgs[i], strdup(name));
		if (ret)
			return ret;

		/* forward to qp 0 */
		fg_fwd_action[i] = mlx5dv_dr_action_create_dest_ibv_qp(rx_qps[0]);
		if (!fg_fwd_action[i])
			return -errno;

		ret = mlx5_tbl_init_with_counter(&last_level_fgs[i].tbl, 3,
		                                  fg_fwd_action[i],
		                                  &cnt_last_level_fgs[i]);
		if (ret)
			return ret;

		last_level_fgs[i].qp_assignment = 0;
	}

	return 0;
}

static int mlx5_init_udp(void)
{
	int ret;
	union match mask = {0};

	udp_dport_tbl = alloc_port_matcher(IPPROTO_UDP, true, PORT_MATCH_BITS);
	if (!udp_dport_tbl)
		return -EINVAL;

	udp_sport_tbl = alloc_port_matcher(IPPROTO_UDP, false, PORT_MATCH_BITS);
	if (!udp_sport_tbl)
		return -EINVAL;

	ret = mlx5_tbl_init(&udp_tbl, 1, udp_dport_tbl->tbl.ingress_action);
	if (ret)
		return ret;

	mask.size = DEVX_ST_SZ_BYTES(fte_match_param);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_version, 4);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.udp_dport, __devx_mask(16));

	udp_tbl_dport_match = mlx5dv_dr_matcher_create(udp_tbl.tbl, 0,
		    DR_MATCHER_CRITERIA_OUTER, &mask.params);
	if (!udp_tbl_dport_match)
		return -errno;

	return 0;
}

static int mlx5_init_tcp(void)
{
	int ret;
	union match mask = {0};

	tcp_dport_tbl = alloc_port_matcher(IPPROTO_TCP, true, PORT_MATCH_BITS);
	if (!tcp_dport_tbl)
		return -EINVAL;

	tcp_sport_tbl = alloc_port_matcher(IPPROTO_TCP, false, PORT_MATCH_BITS);
	if (!tcp_sport_tbl)
		return -EINVAL;

	ret = mlx5_tbl_init(&tcp_tbl, 1, tcp_dport_tbl->tbl.ingress_action);
	if (ret)
		return ret;

	mask.size = DEVX_ST_SZ_BYTES(fte_match_param);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_version, 4);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.tcp_dport, __devx_mask(16));

	tcp_tbl_dport_match = mlx5dv_dr_matcher_create(tcp_tbl.tbl, 0,
		    DR_MATCHER_CRITERIA_OUTER, &mask.params);
	if (!tcp_tbl_dport_match)
		return -errno;

	return 0;
}

static int mlx5_init_root_table(void)
{
	union match mask = {0};
	struct mlx5dv_dr_action *actions[2];
	int ret;

	log_info("\n=== INITIALIZING ROOT FLOW STEERING TABLE ===");
	log_info("Runtime IP: %u.%u.%u.%u (0x%08x)",
	         (netcfg.addr >> 24) & 0xFF,
	         (netcfg.addr >> 16) & 0xFF,
	         (netcfg.addr >> 8) & 0xFF,
	         netcfg.addr & 0xFF,
	         netcfg.addr);

	/* Allocate counters for root table rules */
	ret = alloc_flow_counter(&cnt_root_tcp, "root_tcp");
	if (ret)
		return ret;
	ret = alloc_flow_counter(&cnt_root_udp, "root_udp");
	if (ret)
		return ret;

	mask.size = DEVX_ST_SZ_BYTES(fte_match_param);
	/* DIAG: only match on ip_protocol to test which field is broken */
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_protocol, __devx_mask(8));
	match_ip_and_tport = mlx5dv_dr_matcher_create(root_tbl, 0, DR_MATCHER_CRITERIA_OUTER, &mask.params);
	if (!match_ip_and_tport)
		return -errno;

	log_info("\n--- ROOT TABLE RULE 1: TCP ---");
	log_info("  Match: dst_ip=%u.%u.%u.%u, protocol=TCP",
	         (netcfg.addr >> 24) & 0xFF,
	         (netcfg.addr >> 16) & 0xFF,
	         (netcfg.addr >> 8) & 0xFF,
	         netcfg.addr & 0xFF);
	log_info("  Action: count + forward to tcp_tbl (level 1)");

	/* DIAG: only set ip_protocol value */
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_protocol, IPPROTO_TCP);
	actions[0] = cnt_root_tcp.action;
	actions[1] = tcp_tbl.ingress_action;
	root_tcp_rule = mlx5dv_dr_rule_create(match_ip_and_tport, &mask.params, 2, actions);
	if (!root_tcp_rule) {
		log_err("FAILED to create root TCP rule, errno=%d (%s)", errno, strerror(errno));
		return -errno;
	}
	log_info("  Rule handle: %p, counter_id: %u - SUCCESS", root_tcp_rule, cnt_root_tcp.id);

	log_info("\n--- ROOT TABLE RULE 2: UDP ---");
	log_info("  Match: dst_ip=%u.%u.%u.%u, protocol=UDP",
	         (netcfg.addr >> 24) & 0xFF,
	         (netcfg.addr >> 16) & 0xFF,
	         (netcfg.addr >> 8) & 0xFF,
	         netcfg.addr & 0xFF);
	log_info("  Action: count + forward to udp_tbl (level 1)");

	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_protocol, IPPROTO_UDP);
	actions[0] = cnt_root_udp.action;
	actions[1] = udp_tbl.ingress_action;
	root_udp_rule = mlx5dv_dr_rule_create(match_ip_and_tport, &mask.params, 2, actions);
	if (!root_udp_rule) {
		log_err("FAILED to create root UDP rule, errno=%d (%s)", errno, strerror(errno));
		return -errno;
	}
	log_info("  Rule handle: %p, counter_id: %u - SUCCESS", root_udp_rule, cnt_root_udp.id);

	log_info("\n=== ROOT TABLE INITIALIZATION COMPLETE ===\n");

	/* DIAGNOSTIC: catch-all rule to test if DR pipeline is connected */
	{
		struct mlx5dv_dr_matcher *catchall_matcher;
		struct mlx5dv_dr_rule *catchall_rule;
		struct mlx5dv_dr_action *catchall_actions[2];

		ret = alloc_flow_counter(&cnt_catchall, "catchall");
		if (ret) {
			log_err("DIAG: failed to allocate catchall counter");
		} else {
			catchall_matcher = mlx5dv_dr_matcher_create(root_tbl, 1,
				DR_MATCHER_CRITERIA_EMPTY, &empty_match.params);
			if (!catchall_matcher) {
				log_err("DIAG: failed to create catchall matcher, errno=%d", errno);
			} else {
				catchall_actions[0] = cnt_catchall.action;
				catchall_actions[1] = udp_tbl.ingress_action;
				catchall_rule = mlx5dv_dr_rule_create(catchall_matcher,
					&empty_match.params, 2, catchall_actions);
				if (!catchall_rule) {
					log_err("DIAG: failed to create catchall rule, errno=%d", errno);
				} else {
					log_info("DIAG: catch-all rule created at priority 1");
				}
			}
		}
	}

	return 0;
}

static int mlx5_register_flow(unsigned int affinity, struct trans_entry *e, void **handle_out)
{
	union match key = {0};

	struct port_matcher_tbl *dst_tbl;
	bitmap_ptr_t map;
	struct mlx5dv_dr_matcher *match;
	struct mlx5dv_dr_action *action[1];
	void *rule;

	if (e->match != TRANS_MATCH_3TUPLE)
		return -EINVAL;

	/* validate affinity is within range */
	if (affinity >= maxks) {
		log_err("mlx5_register_flow: invalid affinity %u (maxks=%u)", affinity, maxks);
		return -EINVAL;
	}

	key.size = DEVX_ST_SZ_BYTES(fte_match_param);
	DEVX_SET(fte_match_param, key.buf, outer_headers.ip_version, 4);

	const char *proto_str;
	switch (e->proto) {
		case IPPROTO_TCP:
			map = tcp_listen_ports;
			match = tcp_tbl_dport_match;
			dst_tbl = tcp_sport_tbl;
			DEVX_SET(fte_match_param, key.buf, outer_headers.tcp_dport, e->laddr.port);
			proto_str = "TCP";
			break;
		case IPPROTO_UDP:
			map = udp_listen_ports;
			match = udp_tbl_dport_match;
			dst_tbl = udp_sport_tbl;
			DEVX_SET(fte_match_param, key.buf, outer_headers.udp_dport, e->laddr.port);
			proto_str = "UDP";
			break;
		default:
			return -EINVAL;
	}

	if (bitmap_atomic_test_and_set(map, e->laddr.port)) {
		log_warn("mlx5_register_flow: port %u already registered!", e->laddr.port);
		return -EINVAL;
	}

	/* Route directly to the flow group for the specified affinity,
	 * bypassing source port hashing */
	log_info("=== INSTALLING FLOW RULE ===");
	log_info("  Protocol: %s", proto_str);
	log_info("  Dst Port: %u", e->laddr.port);
	log_info("  Affinity (kthread): %u", affinity);
	log_info("  QP assignment: %u", last_level_fgs[affinity].qp_assignment);
	log_info("  Action: forward to last_level_fgs[%u] table -> rx_qps[%u]",
	         affinity, last_level_fgs[affinity].qp_assignment);

	action[0] = last_level_fgs[affinity].tbl.ingress_action;

	spin_lock_np(&direct_rule_lock);
	rule = mlx5dv_dr_rule_create(match, &key.params, 1, action);
	spin_unlock_np(&direct_rule_lock);


	if (!rule) {
		log_err("mlx5_register_flow: FAILED to create rule for port %u, errno=%d (%s)",
		        e->laddr.port, errno, strerror(errno));
		bitmap_atomic_clear(map, e->laddr.port);
		return -errno;
	}

	log_info("  Rule handle: %p - SUCCESS", rule);
	log_info("============================");

	*handle_out = rule;

    /* Sync new rule to hardware */
	mlx5dv_dr_domain_sync(dmn, MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW);
	mlx5dv_dr_domain_sync(dmn, MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW);
	log_info("  Domain sync completed after register_flow");

	return 0;
}

static int mlx5_deregister_flow(struct trans_entry *e, void *handle)
{
	int ret;

	if (e->proto == IPPROTO_TCP)
		bitmap_atomic_clear(tcp_listen_ports, e->laddr.port);
	else if (e->proto == IPPROTO_UDP)
		bitmap_atomic_clear(udp_listen_ports, e->laddr.port);
	else
		return -EINVAL;

	spin_lock_np(&direct_rule_lock);
	ret = mlx5dv_dr_rule_destroy(handle);
	spin_unlock_np(&direct_rule_lock);

	return ret;
}

static int mlx5_steer_flows(unsigned int *new_fg_assignment)
{
	int i, ret = 0;
	struct ibv_qp *new_qp, *old_qp;
	struct last_level_fg *fg;

	log_info("mlx5_steer_flows: Redistributing flow groups across kthreads");
	postsend_lock(dmn);

	for (i = 0; i < maxks; i++) {
		fg = &last_level_fgs[i];

		if (new_fg_assignment[i] == fg->qp_assignment)
			continue;

		log_info("  FG %d: reassigning from kthread %d -> %d", i, fg->qp_assignment, new_fg_assignment[i]);
		new_qp = rx_qps[new_fg_assignment[i]];
		old_qp = rx_qps[fg->qp_assignment];

		ret = switch_qp_action(fg->tbl.default_egress_rule, dmn,
			    new_qp, old_qp);
		if (unlikely(ret)) {
			log_err("  switch_qp_action failed with ret=%d", ret);
			break;
		}

		fg->qp_assignment = new_fg_assignment[i];
	}

	postsend_unlock(dmn);

	return ret;

}

static uint32_t mlx5_get_flow_affinity(uint8_t ipproto, uint16_t local_port, struct netaddr remote)
{
	bitmap_ptr_t map = ipproto == IPPROTO_TCP ? tcp_listen_ports :
			  udp_listen_ports;

	if (bitmap_atomic_test(map, local_port))
		return (remote.port & PORT_MASK) % maxks;
	else
		return (local_port & PORT_MASK) % maxks;
}

static int mlx5_init_flows(void)
{
	int ret;

	spin_lock_init(&direct_rule_lock);

	ret = mlx5_init_fg_tables();
	if (ret)
		return ret;

	ret = mlx5_init_udp();
	if (ret)
		return ret;

	ret = mlx5_init_tcp();
	if (ret)
		return ret;

	ret = mlx5_init_root_table();
	if (ret)
		return ret;

	ret = mlx5dv_dr_domain_sync(dmn, MLX5DV_DR_DOMAIN_SYNC_FLAGS_SW);
	log_info("mlx5dv_dr_domain_sync(SW) returned %d (errno=%d)", ret, errno);
	if (ret)
		return ret;

	ret = mlx5dv_dr_domain_sync(dmn, MLX5DV_DR_DOMAIN_SYNC_FLAGS_HW);
	log_info("mlx5dv_dr_domain_sync(HW) returned %d (errno=%d)", ret, errno);
	if (ret)
		return ret;

	log_info("=== DR DOMAIN SYNC COMPLETE - rules should be in hardware ===");
	return 0;

}

bool mlx5_sw_flow_steering_early_init(void)
{
	struct mlx5dv_dr_table *test_sw_tbl;

	RT_FS_DBG("=== mlx5_sw_flow_steering_early_init: START ===");

    struct mlx5dv_context dv_ctx = { 0 };
    dv_ctx.comp_mask = 0;
    mlx5dv_query_device(context, &dv_ctx);
    log_info("DEVX flags: 0x%lx", (unsigned long)dv_ctx.flags);

	errno = 0;
	dmn = mlx5dv_dr_domain_create(context,
		MLX5DV_DR_DOMAIN_TYPE_NIC_RX);

	log_info("RUNTIME DR domain create: %s (dmn=%p, errno=%d: %s)",
	         dmn ? "SUCCESS" : "FAILED", dmn, errno, strerror(errno));
	if (!dmn) {
		RT_FS_DBG("DR domain create FAILED (errno=%d)", errno);
		return false;
	}
	RT_FS_DBG("DR domain created: dmn=%p", dmn);

	errno = 0;
	root_tbl = mlx5dv_dr_table_create(dmn, 0);
	log_info("RUNTIME root table create (level 0): %s (root_tbl=%p, errno=%d: %s)",
	         root_tbl ? "SUCCESS" : "FAILED", root_tbl, errno, strerror(errno));
	if (!root_tbl) {
		RT_FS_DBG("Root table create (level 0) FAILED (errno=%d)", errno);
		goto out_destroy_domain;
	}
	RT_FS_DBG("Root table created (level 0): root_tbl=%p", root_tbl);

	errno = 0;
	test_sw_tbl = mlx5dv_dr_table_create(dmn, 1);
	log_info("RUNTIME test SW table create (level 1): %s (test_sw_tbl=%p, errno=%d: %s)",
	         test_sw_tbl ? "SUCCESS" : "FAILED", test_sw_tbl, errno, strerror(errno));
	if (!test_sw_tbl) {
		RT_FS_DBG("Test SW table create (level 1) FAILED (errno=%d)", errno);
		goto out_destroy_hw_tbl;
	}
	RT_FS_DBG("Test SW table created (level 1): SUCCESS");

	mlx5dv_dr_table_destroy(test_sw_tbl);
	RT_FS_DBG("=== mlx5_sw_flow_steering_early_init: SUCCESS ===");
	return true;

out_destroy_hw_tbl:
	mlx5dv_dr_table_destroy(root_tbl);
out_destroy_domain:
	mlx5dv_dr_domain_destroy(dmn);
	RT_FS_DBG("=== mlx5_sw_flow_steering_early_init: FAILED ===");
	return false;
}


int mlx5_init_flow_steering(void)
{
	int ret, i;

	RT_FS_DBG("=== mlx5_init_flow_steering: START ===");
	RT_FS_DBG("Runtime IP: %u.%u.%u.%u (0x%08x)",
	          (netcfg.addr >> 24) & 0xFF, (netcfg.addr >> 16) & 0xFF,
	          (netcfg.addr >> 8) & 0xFF, netcfg.addr & 0xFF, netcfg.addr);

	ret = mlx5_init_flows();
	if (ret) {
		log_err("Failed to setup mlx5 hardware steering: ret %d", ret);
		RT_FS_DBG("mlx5_init_flows FAILED: ret=%d", ret);
		return ret;
	}
	RT_FS_DBG("mlx5_init_flows: SUCCESS");

	net_ops.steer_flows = mlx5_steer_flows;
	net_ops.register_flow = mlx5_register_flow;
	net_ops.deregister_flow = mlx5_deregister_flow;
	net_ops.get_flow_affinity = mlx5_get_flow_affinity;
	RT_FS_DBG("net_ops registered for flow steering");

	log_info("\n========================================");
	log_info("FLOW STEERING HIERARCHY INITIALIZED");
	log_info("========================================");
	log_info("Level 0 (root_tbl): Match dst_ip + protocol");
	log_info("  -> TCP: forward to tcp_tbl (level 1)");
	log_info("  -> UDP: forward to udp_tbl (level 1)");
	log_info("");
	log_info("Level 1 (tcp_tbl/udp_tbl): Match dst_port");
	log_info("  -> Per-port rules will be added via register_flow()");
	log_info("");
	log_info("Level 2 (port matcher tables): Hash on src_port");
	log_info("  -> %d flow groups created", maxks);
	log_info("");
	log_info("Level 3 (last_level_fgs): Final destination QPs");
	for (i = 0; i < maxks; i++) {
		log_info("  Flow Group %d -> rx_qps[%u]", i, last_level_fgs[i].qp_assignment);
	}
	log_info("========================================\n");

	RT_FS_DBG("=== mlx5_init_flow_steering: COMPLETE ===");
	return 0;
}

/*
 * Query and print all flow counter statistics
 */
void mlx5_print_flow_counters(void)
{
	uint64_t packets, bytes;
	int i, ret;

	log_info("========================================");
	log_info("FLOW STEERING HIT COUNTERS");
	log_info("========================================");

	/* Level 0: Root table counters */
	log_info("Level 0 (root_tbl):");
	ret = query_flow_counter(&cnt_root_tcp, &packets, &bytes);
	if (ret == 0)
		log_info("  TCP:  %lu packets, %lu bytes", packets, bytes);
	else
		log_info("  TCP:  query failed (ret=%d)", ret);

	ret = query_flow_counter(&cnt_root_udp, &packets, &bytes);
	if (ret == 0)
		log_info("  UDP:  %lu packets, %lu bytes", packets, bytes);
	else
		log_info("  UDP:  query failed (ret=%d)", ret);

	/* DIAGNOSTIC: catch-all counter */
	ret = query_flow_counter(&cnt_catchall, &packets, &bytes);
	if (ret == 0)
		log_info("  CATCH-ALL:  %lu packets, %lu bytes", packets, bytes);
	else
		log_info("  CATCH-ALL:  query failed (ret=%d)", ret);

	/* Level 3: Last level flow group counters */
	log_info("Level 3 (last_level_fgs):");
	for (i = 0; i < maxks; i++) {
		ret = query_flow_counter(&cnt_last_level_fgs[i], &packets, &bytes);
		if (ret == 0)
			log_info("  FG[%d] -> QP[%u]: %lu packets, %lu bytes",
			         i, last_level_fgs[i].qp_assignment, packets, bytes);
		else
			log_info("  FG[%d]: query failed (ret=%d)", i, ret);
	}

	log_info("========================================\n");
}

/*
 * Worker thread that periodically prints flow counter statistics
 */
static void flow_counter_print_worker(void *arg)
{
	/* Wait a bit before first print to let system stabilize */
	timer_sleep(FLOW_COUNTER_PRINT_INTERVAL_US);

	while (true) {
		mlx5_print_flow_counters();
		timer_sleep(FLOW_COUNTER_PRINT_INTERVAL_US);
	}
}

/*
 * Start the periodic flow counter printing thread
 * Should be called after runtime is fully initialized
 */
int mlx5_start_flow_counter_monitor(void)
{
	return thread_spawn(flow_counter_print_worker, NULL);
}

#endif
