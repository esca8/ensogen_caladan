/*
 * steering.c - main steering rules for directpath contexts
 */

#ifdef DIRECTPATH

#include <net/arp.h>
#include <net/ip.h>

#include "../defs.h"

#include "defs.h"
#include "mlx5_ifc.h"

/* Debug flag for flow steering - set to 1 to enable debug prints */
#ifndef FS_DEBUG
#define FS_DEBUG 1
#endif

#if FS_DEBUG
#define FS_DBG(fmt, ...) log_info("[FS_DBG] " fmt, ##__VA_ARGS__)
#else
#define FS_DBG(fmt, ...) do { } while (0)
#endif

static bool use_legacy_steering;

// Flow steering
#define FLOW_TBL_TYPE 0x0
#define FLOW_TBL_LOG_ENTRIES 12
#define FLOW_TBL_NR_ENTRIES (1 << FLOW_TBL_LOG_ENTRIES)
BUILD_ASSERT(IOKERNEL_MAX_PROC <= FLOW_TBL_NR_ENTRIES);

/* flow steering stuff */
struct mlx5dv_devx_obj *root_flow_tbl;
struct mlx5dv_devx_obj *root_flow_group;
static struct mlx5dv_dr_domain *dr_dmn;
static struct mlx5dv_dr_matcher *matcher;
static struct mlx5dv_dr_table *main_sw_tbl;
static struct mlx5dv_devx_obj *root_flow_rule;

/* legacy steering */
static struct mlx5dv_devx_obj *legacy_hw_tbl;
static struct mlx5dv_devx_obj *legacy_flow_group;
static DEFINE_BITMAP(ft_used_entries, FLOW_TBL_NR_ENTRIES);

static struct mlx5dv_devx_obj *create_hardware_table(uint32_t level,
	uint32_t log_size)
{
    printf("iokerneL: create_hw_tabe!!\n");
	struct mlx5dv_devx_obj *obj;
	uint32_t in[DEVX_ST_SZ_DW(create_flow_table_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_flow_table_out)] = {0};
	void *ftc;

	FS_DBG("create_hardware_table: level=%u, log_size=%u", level, log_size);

	DEVX_SET(create_flow_table_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_TABLE);
	DEVX_SET(create_flow_table_in, in, table_type, FLOW_TBL_TYPE /* NIC RX */);
	ftc = DEVX_ADDR_OF(create_flow_table_in, in, flow_table_context);

	DEVX_SET(flow_table_context, ftc, table_miss_action, 0);
	DEVX_SET(flow_table_context, ftc, level, level);
	DEVX_SET(flow_table_context, ftc, log_size, log_size);

	obj = mlx5dv_devx_obj_create(vfcontext, in, sizeof(in), out, sizeof(out));
	if (!obj) {
		LOG_CMD_FAIL("failed to create root flow tbl", create_flow_table_out,
			out);
		FS_DBG("create_hardware_table: FAILED (errno=%d)", errno);
		return NULL;
	}

	FS_DBG("create_hardware_table: SUCCESS, obj_id=%u", mlx5_devx_get_obj_id(obj));
	return obj;
}

static int setup_hardware_flow_group(uint32_t table_number, uint32_t *group_id)
{
	uint32_t in[DEVX_ST_SZ_DW(create_flow_group_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_flow_group_out)] = {0};

	FS_DBG("setup_hardware_flow_group: table_id=%u, match=ethertype", table_number);

	DEVX_SET(create_flow_group_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_GROUP);
	DEVX_SET(create_flow_group_in, in, table_type, FLOW_TBL_TYPE);
	DEVX_SET(create_flow_group_in, in, table_id, table_number);
	DEVX_SET(create_flow_group_in, in, match_criteria_enable, DR_MATCHER_CRITERIA_OUTER);
	DEVX_SET(create_flow_group_in, in, start_flow_index, 0);
	DEVX_SET(create_flow_group_in, in, end_flow_index, 1);

	DEVX_SET(create_flow_group_in, in, match_criteria.outer_headers.ethertype,
		     __devx_mask(16));

	root_flow_group = mlx5dv_devx_obj_create(vfcontext, in, sizeof(in),
		out, sizeof(out));
	if (!root_flow_group) {
		LOG_CMD_FAIL("flow group", create_flow_group_out, out);
		FS_DBG("setup_hardware_flow_group: FAILED (errno=%d)", errno);
		return -1;
	}

	*group_id = DEVX_GET(create_flow_group_out, out, group_id);
	FS_DBG("setup_hardware_flow_group: SUCCESS, group_id=%u", *group_id);
	return 0;
}

static struct mlx5dv_devx_obj *setup_legacy_flow_group(uint32_t table_number)
{
	uint32_t in[DEVX_ST_SZ_DW(create_flow_group_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_flow_group_out)] = {0};
	void *fte_match_param;
	struct mlx5dv_devx_obj *obj;

	DEVX_SET(create_flow_group_in, in, opcode, MLX5_CMD_OP_CREATE_FLOW_GROUP);
	DEVX_SET(create_flow_group_in, in, table_type, FLOW_TBL_TYPE);
	DEVX_SET(create_flow_group_in, in, table_id, table_number);
	DEVX_SET(create_flow_group_in, in, match_criteria_enable, DR_MATCHER_CRITERIA_OUTER);

	DEVX_SET(create_flow_group_in, in, start_flow_index, 0);
	DEVX_SET(create_flow_group_in, in, end_flow_index, FLOW_TBL_NR_ENTRIES - 1);

	fte_match_param = DEVX_ADDR_OF(create_flow_group_in, in, match_criteria);

	DEVX_SET(fte_match_param, fte_match_param,
		     outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4, __devx_mask(32));
	DEVX_SET(fte_match_param, fte_match_param, outer_headers.ethertype,
		     __devx_mask(16));
	DEVX_SET(fte_match_param, fte_match_param, outer_headers.ip_version, __devx_mask(4));

	obj = mlx5dv_devx_obj_create(vfcontext, in, sizeof(in), out, sizeof(out));
	if (!obj) {
		LOG_CMD_FAIL("flow group2", create_flow_group_out, out);
		return NULL;
	}

	return obj;
}

static int setup_hardware_sw_rule(uint32_t root_tbl_id, uint32_t group_id,
	                              uint32_t sw_table_id)
{
	uint32_t in[DEVX_ST_SZ_DW(set_fte_in) + DEVX_ST_SZ_DW(dest_format)] = {};
	uint32_t out[DEVX_ST_SZ_DW(set_fte_out)];
	void *in_flow_context;
	uint8_t *in_dests;

	FS_DBG("=== setup_hardware_sw_rule (ROOT HW TABLE RULE) ===");
	FS_DBG("  root_tbl_id=%u, group_id=%u, dest_sw_table_id=%u",
	       root_tbl_id, group_id, sw_table_id);
	FS_DBG("  -> HW RULE MATCH CRITERIA:");
	FS_DBG("       ethertype = 0x%04x (IPv4)", ETHTYPE_IP);
	FS_DBG("  -> ACTION: FWD to SW table (id=%u)", sw_table_id);

	/* set root h/w-managed flow table to send all packets to the s/w table */
	DEVX_SET(set_fte_in, in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	DEVX_SET(set_fte_in, in, table_type, FLOW_TBL_TYPE);
	DEVX_SET(set_fte_in, in, table_id, root_tbl_id);
	DEVX_SET(set_fte_in, in, flow_index, 0);

	in_flow_context = DEVX_ADDR_OF(set_fte_in, in, flow_context);
	DEVX_SET(flow_context, in_flow_context, group_id, group_id);
	DEVX_SET(flow_context, in_flow_context, action,
		MLX5_FLOW_CONTEXT_ACTION_FWD_DEST);
	DEVX_SET(flow_context, in_flow_context, destination_list_size, 1);
	in_dests = DEVX_ADDR_OF(flow_context, in_flow_context, destination);
	DEVX_SET(dest_format, in_dests, destination_type, MLX5_FLOW_DEST_TYPE_FT);
	DEVX_SET(dest_format, in_dests, destination_id, sw_table_id);

	DEVX_SET(flow_context, in_flow_context, match_value.outer_headers.ethertype,
		ETHTYPE_IP);

	root_flow_rule = mlx5dv_devx_obj_create(vfcontext, in, sizeof(in), out,
		sizeof(out));
	if (!root_flow_rule) {
		LOG_CMD_FAIL("flow group", set_fte_out, out);
		FS_DBG("setup_hardware_sw_rule: FAILED (errno=%d)", errno);
		return -1;
	}

	FS_DBG("setup_hardware_sw_rule: SUCCESS, HW rule installed in root table");
	return 0;
}

int directpath_steering_attach_legacy(struct directpath_ctx *ctx)
{
	uint32_t in[DEVX_ST_SZ_DW(set_fte_in) + DEVX_ST_SZ_DW(dest_format)] = {};
	uint32_t out[DEVX_ST_SZ_DW(set_fte_out)] = {};
	void *in_flow_context;
	uint8_t *in_dests;
	int index;

	index = bitmap_find_next_cleared(ft_used_entries, FLOW_TBL_NR_ENTRIES, 0);
	if (index == FLOW_TBL_NR_ENTRIES) {
		log_err("flow table exhausted!");
		return -ENOMEM;
	}

	DEVX_SET(set_fte_in, in, opcode, MLX5_CMD_OP_SET_FLOW_TABLE_ENTRY);
	DEVX_SET(set_fte_in, in, table_type, FLOW_TBL_TYPE);
	DEVX_SET(set_fte_in, in, table_id, mlx5_devx_get_obj_id(legacy_hw_tbl));
	DEVX_SET(set_fte_in, in, flow_index, index);

	in_flow_context = DEVX_ADDR_OF(set_fte_in, in, flow_context);
	DEVX_SET(flow_context, in_flow_context, group_id, mlx5_devx_get_obj_id(legacy_flow_group));
	DEVX_SET(flow_context, in_flow_context, action, (1 << 2));

	DEVX_SET(flow_context, in_flow_context, match_value.outer_headers.ethertype, ETHTYPE_IP);
	DEVX_SET(flow_context, in_flow_context, match_value.outer_headers.ip_version, 4);
	DEVX_SET(flow_context, in_flow_context,
		match_value.outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4, ctx->p->ip_addr);

	DEVX_SET(flow_context, in_flow_context, destination_list_size, 1);

	in_dests = DEVX_ADDR_OF(flow_context, in_flow_context, destination);
	DEVX_SET(dest_format, in_dests, destination_type, MLX5_FLOW_DEST_TYPE_TIR);
	DEVX_SET(dest_format, in_dests, destination_id, mlx5_devx_get_obj_id(ctx->tir_obj));

	ctx->fte = mlx5dv_devx_obj_create(vfcontext, in, sizeof(in), out, sizeof(out));

	if (!ctx->fte) {
		log_err("couldnt create STE for tir");
		return -1;
	}

	bitmap_set(ft_used_entries, index);
	ctx->ft_idx = index;

	return 0;
}

void directpath_steering_teardown(struct directpath_ctx *ctx)
{
	int ret;

	if (ctx->fwd_rule) {
		ret = mlx5dv_dr_rule_destroy(ctx->fwd_rule);
		if (ret)
			log_warn("failed to destroy flow rule");
	}

	if (ctx->fwd_action) {
		ret = mlx5dv_dr_action_destroy(ctx->fwd_action);
		if (ret)
			log_warn("failed to destroy dr action");
	}

	if (ctx->fte) {
		ret = mlx5dv_devx_obj_destroy(ctx->fte);
		if (ret)
			log_warn("failed to destroy fte");
	}

	if (ctx->ft_idx != -1)
		bitmap_clear(ft_used_entries, ctx->ft_idx);
}

int directpath_steering_attach(struct directpath_ctx *ctx)
{
	struct mlx5dv_dr_action *action[1];
	static union match mask;

	FS_DBG("=== directpath_steering_attach ===");
	FS_DBG("  runtime ip=0x%08x (%u.%u.%u.%u)",
	       ctx->p->ip_addr,
	       (ctx->p->ip_addr >> 24) & 0xFF, (ctx->p->ip_addr >> 16) & 0xFF,
	       (ctx->p->ip_addr >> 8) & 0xFF, ctx->p->ip_addr & 0xFF);

	if (use_legacy_steering) {
		FS_DBG("  -> Using legacy steering path");
		return directpath_steering_attach_legacy(ctx);
	}

	FS_DBG("  -> Using fast (DR) steering path");
	FS_DBG("  -> DR RULE MATCH CRITERIA:");
	FS_DBG("       ethertype = 0x%04x (IPv4)", ETHTYPE_IP);
	FS_DBG("       ip_version = 4");
	FS_DBG("       dst_ip = 0x%08x (%u.%u.%u.%u)",
	       ctx->p->ip_addr,
	       (ctx->p->ip_addr >> 24) & 0xFF, (ctx->p->ip_addr >> 16) & 0xFF,
	       (ctx->p->ip_addr >> 8) & 0xFF, ctx->p->ip_addr & 0xFF);
	FS_DBG("  -> ACTION: FWD to TIR (fwd_action=%p)", ctx->fwd_action);

	mask.size = DEVX_ST_SZ_BYTES(dr_match_param);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ethertype, ETHTYPE_IP);
	DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_version, 4);
	DEVX_SET(fte_match_param, mask.buf,
		outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4, ctx->p->ip_addr);

	action[0] = ctx->fwd_action;
	errno = 0;
	ctx->fwd_rule = mlx5dv_dr_rule_create(matcher, &mask.params, 1, action);
	if (unlikely(!ctx->fwd_rule)) {
		log_warn("warning: unable to create traffic rule for new proc");
		log_warn("IOKERNEL DR rule creation FAILED (errno=%d: %s)", errno, strerror(errno));
		FS_DBG("  DR rule creation FAILED (errno=%d)", errno);
	} else {
		log_info("IOKERNEL DR rule created SUCCESS for IP %u.%u.%u.%u -> TIR (fwd_rule=%p)",
		         (ctx->p->ip_addr >> 24) & 0xFF, (ctx->p->ip_addr >> 16) & 0xFF,
		         (ctx->p->ip_addr >> 8) & 0xFF, ctx->p->ip_addr & 0xFF,
		         ctx->fwd_rule);
		FS_DBG("  DR rule created SUCCESS, fwd_rule=%p", ctx->fwd_rule);
	}

	return 0;
}


int directpath_setup_steering(void)
{
	int ret;
	uint32_t root_tbl_number, root_fg_id;
	union match mask = {0};

	FS_DBG("=== directpath_setup_steering: START ===");

	root_flow_tbl = create_hardware_table(0, 1);
	if (!root_flow_tbl)
		return -1;

	root_tbl_number = mlx5_devx_get_obj_id(root_flow_tbl);
	FS_DBG("Root HW flow table created: tbl_id=%u", root_tbl_number);

	ret = setup_hardware_flow_group(root_tbl_number, &root_fg_id);
	if (ret)
		return ret;

	/* setup direct flow steering */
	FS_DBG("Creating DR domain for NIC_RX...");
	errno = 0;
	dr_dmn = mlx5dv_dr_domain_create(vfcontext,
			                         MLX5DV_DR_DOMAIN_TYPE_NIC_RX);
	log_info("IOKERNEL DR domain create: %s (dr_dmn=%p, errno=%d: %s)",
	         dr_dmn ? "SUCCESS" : "FAILED", dr_dmn, errno, strerror(errno));
	FS_DBG("DR domain create: %s (dr_dmn=%p)", dr_dmn ? "SUCCESS" : "FAILED", dr_dmn);

	/* create the main s/w-managed flow table */
	if (dr_dmn) {
		errno = 0;
		main_sw_tbl = mlx5dv_dr_table_create(dr_dmn, 1);
		log_info("IOKERNEL DR SW table create (level 1): %s (main_sw_tbl=%p, id=%u, errno=%d: %s)",
		       main_sw_tbl ? "SUCCESS" : "FAILED", main_sw_tbl,
		       main_sw_tbl ? mlx5dv_dr_table_get_id(main_sw_tbl) : 0,
		       errno, strerror(errno));
		FS_DBG("DR SW table create (level 1): %s (main_sw_tbl=%p, id=%u)",
		       main_sw_tbl ? "SUCCESS" : "FAILED", main_sw_tbl,
		       main_sw_tbl ? mlx5dv_dr_table_get_id(main_sw_tbl) : 0);
	}

	use_legacy_steering = !dr_dmn || !main_sw_tbl;
	log_info("directpath: using %s steering", use_legacy_steering ? "legacy" : "fast");
	FS_DBG("Steering mode: %s", use_legacy_steering ? "LEGACY" : "FAST (DR)");

	if (!use_legacy_steering) {
		/* create the matcher that runtime rules will use */
		FS_DBG("Creating DR matcher (match: dst_ip, ethertype, ip_version)...");
		mask.size = DEVX_ST_SZ_BYTES(dr_match_param);
		DEVX_SET(fte_match_param, mask.buf,
			     outer_headers.dst_ipv4_dst_ipv6.ipv4_layout.ipv4,
			     __devx_mask(32));
		DEVX_SET(fte_match_param, mask.buf, outer_headers.ethertype,
			     __devx_mask(16));
		DEVX_SET(fte_match_param, mask.buf, outer_headers.ip_version,
			     IPVERSION);

		matcher = mlx5dv_dr_matcher_create(main_sw_tbl, 0,
			                               DR_MATCHER_CRITERIA_OUTER,
			                               &mask.params);
		if (!matcher) {
			FS_DBG("DR matcher create FAILED (errno=%d)", errno);
			return errno ? -errno : -1;
		}
		FS_DBG("DR matcher created: SUCCESS (matcher=%p)", matcher);

		ret = setup_hardware_sw_rule(root_tbl_number, root_fg_id,
			                         mlx5dv_dr_table_get_id(main_sw_tbl));
		if (ret)
			return ret;
	} else {
		legacy_hw_tbl = create_hardware_table(1, FLOW_TBL_LOG_ENTRIES );
		if (!legacy_hw_tbl)
			return -1;

		ret = setup_hardware_sw_rule(root_tbl_number, root_fg_id,
			                         mlx5_devx_get_obj_id(legacy_hw_tbl));
		if (ret)
			return ret;

		legacy_flow_group = setup_legacy_flow_group(mlx5_devx_get_obj_id(legacy_hw_tbl));
		if (!legacy_flow_group)
			return -1;
	}

	FS_DBG("=== directpath_setup_steering: COMPLETE ===");
	return 0;
}


#endif
