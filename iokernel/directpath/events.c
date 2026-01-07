#ifdef DIRECTPATH

#include <base/bitmap.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <util/udma_barrier.h>
#include <util/mmio.h>

#include "defs.h"
#include "mlx5_ifc.h"

#include "../defs.h"

struct eq main_eq;

int page_cmd_efd;

/* Diagnostic counters for packet flow tracing */
struct dp_diag_counters {
	uint64_t eq_polls;              /* Times directpath_events_poll called */
	uint64_t eq_events_total;       /* Total EQEs processed */
	uint64_t eq_comp_events;        /* Completion EQEs */
	uint64_t eq_cmd_events;         /* Command EQEs */
	uint64_t eq_error_events;       /* Error EQEs */
	uint64_t eq_other_events;       /* Other EQEs */
	uint64_t cq_polls;              /* Times CQ polled */
	uint64_t cq_polls_found;        /* CQ polls that found CQE */
	uint64_t cq_polls_empty;        /* CQ polls that found nothing */
	uint64_t cq_arms;               /* Times CQ armed */
	uint64_t last_print_tsc;        /* Last time stats printed */
};

static struct dp_diag_counters diag = {0};

void dp_diag_print(void)
{
	uint64_t now = rdtsc();
	if (now - diag.last_print_tsc < 2000000ULL * cycles_per_us)
		return;
	diag.last_print_tsc = now;

	fprintf(stderr, "\n=== IOKERNEL PACKET FLOW DIAGNOSTICS ===\n");
	fprintf(stderr, "  EQ: polls=%lu events=%lu (comp=%lu cmd=%lu err=%lu other=%lu)\n",
	        diag.eq_polls, diag.eq_events_total,
	        diag.eq_comp_events, diag.eq_cmd_events,
	        diag.eq_error_events, diag.eq_other_events);
	fprintf(stderr, "  CQ: polls=%lu found=%lu empty=%lu arms=%lu\n",
	        diag.cq_polls, diag.cq_polls_found, diag.cq_polls_empty, diag.cq_arms);
	fprintf(stderr, "  Ratios: %.1f%% CQ polls find CQE, %.1f events/poll\n",
	        diag.cq_polls > 0 ? (100.0 * diag.cq_polls_found / diag.cq_polls) : 0,
	        diag.eq_polls > 0 ? ((double)diag.eq_events_total / diag.eq_polls) : 0);
	fprintf(stderr, "==========================================\n\n");
	fflush(stderr);
}

/* Counter increment functions for use by queues.c */
void dp_diag_cq_poll(bool found)
{
	diag.cq_polls++;
	if (found)
		diag.cq_polls_found++;
	else
		diag.cq_polls_empty++;
}

void dp_diag_cq_arm(void)
{
	diag.cq_arms++;
}

static void *monitor_ev(void *arg)
{
	size_t val;
	int pollfd = mlx5dv_vfio_get_events_fd(vfcontext);
	BUG_ON(pollfd < 0);

	struct pollfd fds[2] = {
		{ .fd = pollfd, .events = POLLIN },
		{ .fd = page_cmd_efd, .events = POLLIN}
	};

	while (true) {
		if (poll(fds, 2, -1) > 0) {

			while (read(page_cmd_efd, &val, sizeof(val)) == sizeof(val))
				mlx5_vfio_deliver_event(vfcontext, 31);

			mlx5dv_vfio_process_events(vfcontext);
			log_debug("vfio: polled some events");
		}
	}
}

static void free_eq(struct eq *eq)
{
	int ret;

	if (eq->eq) {
		ret = mlx5dv_devx_destroy_eq(eq->eq);
		if (ret)
			log_warn("couldn't free eq");
	}

	if (eq->vec) {
		ret = mlx5dv_devx_free_msi_vector(eq->vec);
		if (ret)
			log_warn("couldn't free msi vector");
	}
}

static int create_eq(struct eq *eq)
{
	uint32_t i;
	uint32_t in[DEVX_ST_SZ_DW(create_eq_in)] = {0};
	uint32_t out[DEVX_ST_SZ_DW(create_eq_out)] = {0};
	void *eqc;

	eq->vec = mlx5dv_devx_alloc_msi_vector(vfcontext);
	if (!eq->vec) {
		log_err("failed to alloc msi vec");
		return -1;
	}

	DEVX_SET(create_eq_in, in, opcode, MLX5_CMD_OP_CREATE_EQ);

	eqc = DEVX_ADDR_OF(create_eq_in, in, eq_context_entry);

	DEVX_SET(eqc, eqc, log_eq_size, LOG_EQ_SIZE);
	DEVX_SET(eqc, eqc, uar_page, admin_uar->page_id);
	DEVX_SET(eqc, eqc, intr, eq->vec->vector);

	DEFINE_BITMAP(events, MLX5_EVENT_TYPE_MAX);
	bitmap_init(events, MLX5_EVENT_TYPE_MAX, false);

	bitmap_set(events, MLX5_EVENT_TYPE_SQ_DRAINED);
	bitmap_set(events, MLX5_EVENT_TYPE_SRQ_LAST_WQE);
	bitmap_set(events, MLX5_EVENT_TYPE_SRQ_RQ_LIMIT);
	bitmap_set(events, MLX5_EVENT_TYPE_CQ_ERROR);
	bitmap_set(events, MLX5_EVENT_TYPE_SRQ_CATAS_ERROR);
	bitmap_set(events, MLX5_EVENT_TYPE_DB_BF_CONGESTION);
	bitmap_set(events, MLX5_EVENT_TYPE_CMD);

	bitmap_set(events, MLX5_EVENT_TYPE_WQ_CATAS_ERROR);
	bitmap_set(events, MLX5_EVENT_TYPE_WQ_INVAL_REQ_ERROR);
	bitmap_set(events, MLX5_EVENT_TYPE_WQ_ACCESS_ERROR);
	bitmap_set(events, MLX5_EVENT_TYPE_STALL_EVENT);

	for (i = 0; i < 4; i++)
		DEVX_ARRAY_SET64(create_eq_in, in, event_bitmask, i,
						 events[i]);

	eq->eq = mlx5dv_devx_create_eq(vfcontext, in, sizeof(in), out, sizeof(out));
	if (!eq->eq) {
		LOG_CMD_FAIL("failed to create eq", create_eq_out, out);
		return -1;
	}

	for (i = 0; i < (1U << LOG_EQ_SIZE); i++) {
		struct mlx5_eqe *eqe = eq->eq->vaddr + i * MLX5_EQE_SIZE;
		eqe->owner = 1;
	}

	eq->eqn = DEVX_GET(create_eq_out, out, eq_number);
	eq->nent = 1 << LOG_EQ_SIZE;

	return 0;
}

static struct mlx5_eqe *get_eqe(struct eq *eq, uint32_t idx)
{
	return eq->eq->vaddr + idx * MLX5_EQE_SIZE;
}

static struct mlx5_eqe *get_head_eqe(struct eq *eq)
{
	struct mlx5_eqe *eqe;

	eqe = get_eqe(eq, eq->cons_idx & (eq->nent - 1));
	if ((ACCESS_ONCE(eqe->owner) & 1) ^ !!(eq->cons_idx & eq->nent))
		return NULL;

	udma_from_device_barrier();

	return eqe;
}

static void eq_update_ci(struct eq *eq, int arm)
{
	__be32 *addr = (admin_uar->base_addr + MLX5_EQ_DOORBEL_OFFSET) + (arm ? 0 : 2);
	uint32_t val;

	val = (eq->cons_idx & 0xffffff) | (eq->eqn << 24);

	mmio_write32_be(addr, htobe32(val));
	udma_to_device_barrier();
}

bool directpath_events_poll(void)
{
	unsigned int i, nr_compl = 0;
	struct eq *eq = &main_eq;
	struct mlx5_eqe *eqe;

	struct mlx5_eqe *eqes[POLL_EQ_BATCH_SIZE];

	diag.eq_polls++;

	for (i = 0; i < POLL_EQ_BATCH_SIZE; i++) {
		eqe = get_head_eqe(eq);
		if (!eqe)
			break;

		diag.eq_events_total++;

		switch (eqe->type) {
			case MLX5_EVENT_TYPE_COMP:
				eqes[nr_compl++] = eqe;
				diag.eq_comp_events++;
				break;
			case MLX5_EVENT_TYPE_CMD:
				directpath_handle_cmd_eqe(eqe);
				diag.eq_cmd_events++;
				break;
			case MLX5_EVENT_TYPE_CQ_ERROR:
				directpath_handle_cq_error_eqe(eqe);
				diag.eq_error_events++;
				break;
			case MLX5_EVENT_TYPE_SRQ_LAST_WQE:
				log_err("got last wqe %hhu pn %u", eqe->data.qp.type, be32toh(eqe->data.qp.qpn_rqn_sqn) & 0xffffff);
				diag.eq_other_events++;
				break;
			default:
				log_err("got an eqe! eqe->type: %hhu (%u)", eqe->type, eq->cons_idx);
				diag.eq_other_events++;
				break;
		}

		eq->cons_idx++;
	}

	if (i > 0) {
		STAT_INC(DIRECTPATH_EVENTS, i);

		if (nr_compl)
			directpath_handle_completion_eqe_batch(eqes, nr_compl);

		eq_update_ci(eq, 0);
	}

	dp_diag_print();

	return i > 0;
}

int events_init(void)
{
	int ret;
	pthread_t mon_thread;

	page_cmd_efd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
	if (page_cmd_efd < 0)
		return -1;

	ret = pthread_create(&mon_thread, NULL, monitor_ev, NULL);
	if (ret) {
		log_err("events_init: pthread_create failed");
		return ret;
	}

	ret = create_eq(&main_eq);
	if (ret) {
		log_err("couldn't create eq");
		free_eq(&main_eq);
		return ret;
	}

	return 0;
}

#endif
