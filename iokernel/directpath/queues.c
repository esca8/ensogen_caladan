#ifdef DIRECTPATH

#include <signal.h>

#include <base/byteorder.h>
#include <util/mmio.h>
#include <util/udma_barrier.h>

#include "../defs.h"
#include "../sched.h"
#include "../hw_timestamp.h"
#include "defs.h"
#include "mlx5_ifc.h"

#define QUEUE_DEMOTION_US 1500
#define QUEUE_PROMOTION_US 300

static void directpath_arm_queue(struct directpath_ctx *ctx, struct cq *cq, uint32_t cons_idx)
{
	uint64_t doorbell;
	uint32_t sn;
	uint32_t ci;
	uint32_t cmd;

	assert(!bitmap_test(ctx->armed_rx_queues, cq->qp_idx));

	sn  = cq->arm_sn++ & 3;
	ci  = cons_idx & 0xffffff;
	cmd = MLX5_CQ_DB_REQ_NOT;

	doorbell = sn << 28 | cmd | ci;
	doorbell <<= 32;
	doorbell |= cq->cqn;

	cq->dbrec[1] = htobe32(sn << 28 | cmd | ci);

	barrier();
	mmio_write64_be(admin_uar->base_addr + MLX5_CQ_DOORBELL, htobe64(doorbell));
	barrier();
	bitmap_set(ctx->armed_rx_queues, cq->qp_idx);
	ctx->nr_armed++;
}

static void directpath_enable_queue(struct directpath_ctx *ctx, unsigned int idx)
{
	struct cq *cq = &ctx->qps[idx].rx_cq;

	if (cq->state == RXQ_STATE_DISABLED)
		ctx->disabled_rx_count--;

	cq->state = RXQ_STATE_ACTIVE;
	ctx->active_rx_count++;
	bitmap_set(ctx->active_rx_queues, idx);
	++ctx->sw_rss_gen;
}

static void directpath_disable_queue(struct directpath_ctx *ctx, unsigned int idx)
{
	struct cq *cq = &ctx->qps[idx].rx_cq;

	cq->disable_gen = ++ctx->sw_rss_gen;
	cq->state = RXQ_STATE_DISABLING;
	ctx->active_rx_count--;
	bitmap_clear(ctx->active_rx_queues, idx);
}

static void directpath_queue_update_state(struct directpath_ctx *ctx,
                                          struct thread *th, unsigned int idx,
                                          uint64_t cur_tsc)
{
	struct cq *cq = &ctx->qps[idx].rx_cq;

	if (cq->state == RXQ_STATE_DISABLING &&
	    cq->disable_gen <= ctx->hw_rss_gen) {
		cq->state = RXQ_STATE_DISABLED;
		ctx->disabled_rx_count++;
	}

	if (th->active) {
		if (cq->state != RXQ_STATE_ACTIVE &&
		    cur_tsc - th->change_tsc > QUEUE_PROMOTION_US * cycles_per_us)
			directpath_enable_queue(ctx, idx);
	} else {
		if (ctx->active_rx_count > 1 &&
		    cq->state == RXQ_STATE_ACTIVE &&
		    cur_tsc - th->change_tsc > QUEUE_DEMOTION_US * cycles_per_us)
			directpath_disable_queue(ctx, idx);
	}
}

/* NOTE: TX stats tracking
 * TX happens in the runtime (mlx5_transmit_one), not iokernel.
 * To populate TX counters, add tracking in:
 *   runtime/net/directpath/mlx5/mlx5_rxtx.c:mlx5_transmit_one()
 * and expose counters via shared memory or update them directly
 * in the iokernel's directpath_ctx->qps[i].tx_cq fields.
 */

static uint64_t directpath_poll_cq_delay(struct directpath_ctx *ctx,
                                         struct thread *th, struct cq *cq,
                                         bool do_arm)
{
	uint32_t cons_idx;
	struct mlx5_cqe64 *cqe;
	static uint64_t pkt_count = 0;
	static uint64_t null_count = 0;

	cons_idx = ACCESS_ONCE(th->q_ptrs->directpath_rx_tail);
	cqe = get_cqe(cq, cons_idx);
	if (!cqe) {
		if (++null_count % 100000000 == 0) {
			fprintf(stderr, "[IOK CQ_POLL] No CQE found (%lu times), cons_idx=%u\n",
			        null_count, cons_idx);
			fflush(stderr);
		}
		if (do_arm) directpath_arm_queue(ctx, cq, cons_idx);
		return 0;
	}

	/* Track packet statistics */
	cq->rx_packets++;
	cq->rx_bytes += be32toh(cqe->byte_cnt);

	/* Print RSS hash (iokernel perspective) */
    uint32_t rss_hash = ntoh32(*((uint32_t *)cqe + 3));
	// if (rss_hash != 0 || ++pkt_count % 10000 == 0) {
	// 	fprintf(stderr, "[IOKERNEL CQE FOUND] CQ %u: RSS hash = 0x%08x (pkt %lu)\n",
	// 	        cq->qp_idx, rss_hash, pkt_count);
	// 	fflush(stderr);
	// }

	return hw_timestamp_delay_us(cqe);
}

void directpath_poll_proc_prefetch(struct proc *p)
{
	if (p->directpath_data)
		prefetch((struct directpath_ctx *)p->directpath_data);
}

void *directpath_poll_proc_prefetch_th0(struct proc *p, uint32_t qidx)
{
	struct directpath_ctx *ctx = (struct directpath_ctx *)p->directpath_data;
	struct cq *cq;

	if (!cfg.vfio_directpath)
		return NULL;

	if (bitmap_test(ctx->armed_rx_queues, qidx))
		return NULL;

	cq = &ctx->qps[qidx].rx_cq;
	prefetch(cq);
	return cq;
}

void directpath_poll_proc_prefetch_th1(void *cqp, uint32_t cons_idx)
{
	struct cq *cq = (struct cq *)cqp;
	struct mlx5_cqe64 *cqe;

	if (cqp == NULL)
		return;

	cqe = &cq->buf[cons_idx & (cq->cqe_cnt - 1)];
	prefetch(cqe);
}

bool directpath_poll_proc(struct proc *p, uint64_t *delay_cycles,
                          uint64_t cur_tsc, bool should_arm)
{
	struct directpath_ctx *ctx = (struct directpath_ctx *)p->directpath_data;
	struct cq *cq;
	struct thread *th;
	uint64_t delay = 0;
	int i;
	static uint64_t last_stats_time = 0;
	static uint64_t poll_count = 0;

	if (++poll_count % 10000000 == 0) {
		fprintf(stderr, "[IOK POLL_PROC] Called %lu times, nr_qs=%u, nr_armed=%u\n",
		        poll_count, ctx->nr_qs, ctx->nr_armed);
		fflush(stderr);
	}

	if (ctx->nr_armed == ctx->nr_qs &&
	    (!cfg.directpath_active_rss || ctx->active_rx_count == 1))
		return true;

	for (i = 0; i < ctx->nr_qs; i++) {
		th = &p->threads[i];
		cq = &ctx->qps[i].rx_cq;

		if (!bitmap_test(ctx->armed_rx_queues, i))
			delay = MAX(directpath_poll_cq_delay(ctx, th, cq, should_arm), delay);

		if (!cfg.directpath_active_rss)
			continue;

		directpath_queue_update_state(ctx, th, i, cur_tsc);
	}

	/* Print stats every 2 seconds */
	if (cur_tsc - last_stats_time > cycles_per_us * 2000000) {
		uint64_t total_rx_packets = 0, total_rx_bytes = 0;
		uint64_t total_tx_packets = 0, total_tx_bytes = 0;

		fprintf(stderr, "\n=== Directpath Queue Stats (PID %d) at %lu us ===\n",
		        p->pid, cur_tsc / cycles_per_us);
		fprintf(stderr, "  Threads: %u  Queues: %u/%u active  Armed: %u\n",
		        p->thread_count, ctx->active_rx_count, ctx->nr_qs, ctx->nr_armed);
		fprintf(stderr, "  RSS gen: sw=%lu hw=%lu\n", ctx->sw_rss_gen, ctx->hw_rss_gen);

		fprintf(stderr, "\n  Per-Queue Status:\n");
		fprintf(stderr, "  Queue | Active | Armed | State      | RX Packets | RX Bytes   | TX Packets | TX Bytes   | CQN\n");
		fprintf(stderr, "  ------|--------|-------|------------|------------|------------|------------|------------|--------\n");
		for (i = 0; i < ctx->nr_qs; i++) {
			cq = &ctx->qps[i].rx_cq;
			struct cq *tx_cq = &ctx->qps[i].tx_cq;
			const char *state_str;
			switch (cq->state) {
				case RXQ_STATE_ACTIVE: state_str = "ACTIVE    "; break;
				case RXQ_STATE_DISABLING: state_str = "DISABLING "; break;
				case RXQ_STATE_DISABLED: state_str = "DISABLED  "; break;
				default: state_str = "UNKNOWN   ";
			}
			fprintf(stderr, "  %5d | %6s | %5s | %s | %10lu | %10lu | %10lu | %10lu | %u\n",
			        i,
			        bitmap_test(ctx->active_rx_queues, i) ? "YES" : "NO ",
			        bitmap_test(ctx->armed_rx_queues, i) ? "YES" : "NO ",
			        state_str,
			        cq->rx_packets,
			        cq->rx_bytes,
			        tx_cq->tx_packets,
			        tx_cq->tx_bytes,
			        cq->cqn);

			total_rx_packets += cq->rx_packets;
			total_rx_bytes += cq->rx_bytes;
			total_tx_packets += tx_cq->tx_packets;
			total_tx_bytes += tx_cq->tx_bytes;
		}
		fprintf(stderr, "  ------|--------|-------|------------|------------|------------|------------|------------|--------\n");
		fprintf(stderr, "  TOTAL |        |       |            | %10lu | %10lu | %10lu | %10lu |\n",
		        total_rx_packets, total_rx_bytes, total_tx_packets, total_tx_bytes);
		fprintf(stderr, "\n");
		last_stats_time = cur_tsc;
	}

	delay *= cycles_per_us;
	*delay_cycles = MAX(*delay_cycles, delay);

	if (ctx->hw_rss_gen < ctx->sw_rss_gen && !directpath_command_queued(ctx))
		directpath_run_commands(ctx);

	return false;

}

static void directpath_handle_completion_eqe(struct mlx5_eqe *eqe)
{
	uint32_t cqn = be32toh(eqe->data.comp.cqn);
	struct directpath_ctx *ctx = cqn_to_cq_map[cqn].ctx;
	struct proc *p = ctx->p;

	if (likely(!ctx->kill) && !sched_threads_active(p))
		sched_add_core(p);

	bitmap_clear(ctx->armed_rx_queues, cqn_to_cq_map[cqn].qp_idx);
	ctx->nr_armed--;
}


void directpath_handle_completion_eqe_batch(struct mlx5_eqe **eqe, unsigned int nr)
{
	struct proc *ps[nr];
	struct cq_map_entry entries[nr];

	unsigned int i;

	if (nr < 2) {
		for (i = 0; i < nr; i++)
			directpath_handle_completion_eqe(eqe[i]);
		return;
	}

	for (i = 0; i < nr + 4; i++) {

		/* prefetch cqn to cq entry */
		if (i < nr)
			prefetch(&cqn_to_cq_map[be32toh(eqe[i]->data.comp.cqn)]);

		/* dereference cqn to cq entry, prefetch cq */
		if (i > 0 && i < nr + 1) {
			entries[i - 1] = cqn_to_cq_map[be32toh(eqe[i - 1]->data.comp.cqn)];
			__builtin_prefetch(entries[i - 1].ctx, 1, 0);
		}

		/* prefetch proc associated with context */
		if (i > 1 && i < nr + 2) {
			ps[i - 2] = entries[i - 2].ctx->p;
			__builtin_prefetch(ps[i - 2], 1, 0);

			/* decrement armed count in context */
			entries[i - 2].ctx->nr_armed--;
			bitmap_clear(entries[i - 2].ctx->armed_rx_queues, entries[i - 2].qp_idx);
		}

		/* add a core if the proc needs it */
		if (i > 2 && i < nr + 3) {
			if (!sched_threads_active(ps[i - 3]))
				prefetch((void *)ps[i - 3]->policy_data);
		}

		/* add a core if the proc needs it */
		if (i > 3) {
			if (!sched_threads_active(ps[i - 4]))
				sched_add_core(ps[i - 4]);
		}


	}
}


void directpath_handle_cq_error_eqe(struct mlx5_eqe *eqe)
{
	uint32_t cqn = be32toh(eqe->data.cq_err.cqn) & 0xffffff;
	struct directpath_ctx *ctx = cqn_to_cq_map[cqn].ctx;
	struct proc *p = ctx->p;
	log_warn("killing proc with cq overrun");
	kill(p->pid, SIGINT);
}

void directpath_notify_waking(struct proc *p, struct thread *th) {}

#endif
