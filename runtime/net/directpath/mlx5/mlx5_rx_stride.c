
#ifdef DIRECTPATH

#include <base/log.h>
#include <base/mem.h>
#include <base/mempool.h>
#include <base/slab.h>
#include <runtime/sync.h>

#include <util/mmio.h>
#include <util/udma_barrier.h>
#include <net/ethernet.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/tcp.h>

#include "mlx5.h"

#define MLX5_MPRQ_LEN_MASK 0x000ffff
#define MLX5_MPRQ_STRIDE_NUM_MASK 0x3fff0000
#define MLX5_MPRQ_STRIDE_NUM_SHIFT 16
#define MLX5_MPRQ_FILLER_MASK 0x80000000

/* number of total buffers in rx mempool */
static size_t nrbufs;
/* array of ref counters for buffers in rx mempool */
static uint16_t *sw_refs;
static size_t nr_hw_refs;
static uint16_t *hw_refs;
BUILD_ASSERT(DIRECTPATH_NUM_STRIDES <= UINT16_MAX);

/* buffers that are currently in use in sw (and not hw) */
static void **sw_pending_buffers;
static uint64_t sw_pending_head;
static uint64_t sw_pending_tail;

static inline bool shared_rmp_enabled(void)
{
	return netcfg.directpath_mode == DIRECTPATH_MODE_EXTERNAL;
}

static struct mlx5_wq *get_rx_wq(struct mlx5_rxq *v)
{
	if (shared_rmp_enabled())
		return &rmp.wq;

	return &v->wq;
}

static inline size_t index_of_buf(void *buf)
{
	assert((uintptr_t)buf >= (uintptr_t)iok.rx_buf);
	assert((uintptr_t)buf < (uintptr_t)iok.rx_buf + iok.rx_len);
	return (buf - (void *)iok.rx_buf) / DIRECTPATH_STRIDE_MODE_BUF_SZ;
}

static inline void *headbuf_from_buf(void *buf)
{
	size_t idx = index_of_buf(buf);
	return (void *)iok.rx_buf + idx * DIRECTPATH_STRIDE_MODE_BUF_SZ;
}

static inline void dec_hw_ref(uint32_t wq_idx, uint64_t count)
{
	assert_preempt_disabled();
	hw_refs[get_current_affinity() * nr_hw_refs + wq_idx] += count;
}

static inline void dec_sw_ref(void *buf, uint64_t count)
{
	size_t idx = index_of_buf(buf);
	assert_preempt_disabled();

	if (shared_rmp_enabled())
		sw_refs[get_current_affinity() * nrbufs + idx] += count;
	else if (__sync_sub_and_fetch(&sw_refs[idx], count) == 0)
		tcache_free(perthread_ptr(directpath_buf_pt), headbuf_from_buf(buf));

}

static inline void ref_reset_hw(uint32_t post_idx)
{
	size_t i;

	for (i = 0; i < maxks; i++)
		hw_refs[i * nr_hw_refs + post_idx] = 0;
}

static inline void ref_reset_sw(void *buf)
{
	size_t i, idx = index_of_buf(buf);

	for (i = 0; i < maxks; i++)
		sw_refs[i * nrbufs + idx] = 0;
}

static inline void ref_reset_normp(void *buf, uint32_t post_idx)
{
	size_t idx = index_of_buf(buf);
	ACCESS_ONCE(sw_refs[idx]) = DIRECTPATH_NUM_STRIDES;
}

static inline uint64_t get_sw_ref(void *buf)
{
	size_t i, idx = index_of_buf(buf), count = 0;

	for (i = 0; i < maxks; i++)
		count += sw_refs[i * nrbufs + idx];

	return count;
}

static inline uint64_t get_hw_ref(uint32_t idx)
{
	size_t i, count = 0;

	for (i = 0; i < maxks; i++)
		count += hw_refs[i * nr_hw_refs + idx];

	return count;
}

static inline void mlx5_stride_post_buf(struct mlx5_wq *wq, void *buf, uint32_t idx)
{
	struct mlx5_mprq_wqe *wseg;

	wseg = wq->buf + (idx << wq->log_stride);
	wseg->dseg.addr = htobe64((unsigned long)buf + rx_mr_offset);
	store_release(&wq->buffers[idx], buf);
}

static void directpath_strided_rx_completion(struct mbuf *m)
{
	preempt_disable();
	if (m->release_data)
		dec_sw_ref(m->head, m->release_data);
	tcache_free(perthread_ptr(mbuf_pt), m);
	preempt_enable();
}

int mlx5_init_rxq_wq_stride(struct mlx5_wq *wq, void *seg_buf, uint32_t *dbr,
	                        uint64_t size, uint32_t stride, uint32_t lkey)
{
	uint32_t i;
	struct mlx5_mprq_wqe *wseg;
	void *buf;

	/* set byte_count and lkey for all descriptors once */
	for (i = 0; i < size; i++) {
		wseg = seg_buf + i * stride;
		wseg->dseg.byte_count = htobe32(DIRECTPATH_STRIDE_MODE_BUF_SZ);
		wseg->dseg.lkey = htobe32(lkey);

		/* fill queue with buffers */
		buf = mempool_alloc(&directpath_buf_mp);
		if (unlikely(!buf))
			return -ENOMEM;

		if (!shared_rmp_enabled())
			ref_reset_normp(buf, i);

		mlx5_stride_post_buf(wq, buf, i);
	}

	if (shared_rmp_enabled()) {
		rmp.rmp_head = size;
		ACCESS_ONCE(runtime_info->directpath_strides_posted) = size;
	}

	udma_to_device_barrier();
	wq->dbr[0] = htobe32(size & 0xffff);
	wq->head = size;
	return 0;
}

static void mlx5_refill_strided_rxq(struct mlx5_rxq *v, uint32_t nrdesc)
{
	uint32_t index;
	void *buf;

	v->wq_tail += nrdesc;

	assert_preempt_disabled();

	while (wraps_gt(v->wq_tail + v->wq.cnt, v->wq.head)) {
		buf = tcache_alloc(perthread_ptr(directpath_buf_pt));
		if (unlikely(!buf)) {
			log_warn_ratelimited("failed to fully refill rxq");
			break;
		}

		index = v->wq.head++ & (v->wq.cnt - 1);
		ref_reset_normp(buf, index);
		mlx5_stride_post_buf(&v->wq, buf, index);
	}

	udma_to_device_barrier();
	v->wq.dbr[0] = htobe32(v->wq.head & 0xffff);
}


static void mlx5_refill_strided_rxq_rmp(void)
{
	struct kthread *k;
	uint32_t idx;
	uint64_t start_head;
	void *buf;

	if (!spin_try_lock_np(&rmp.lock))
		return;

	k = myk();
	start_head = rmp.rmp_head;

	/* scan RX buffer slots to find ones that hardware is done with */
	while (rmp.rmp_tail < rmp.rmp_head) {
		idx = rmp.rmp_tail & (rmp.wq.cnt - 1);
		buf = rmp.wq.buffers[idx];

		if (get_hw_ref(idx) != DIRECTPATH_NUM_STRIDES)
			break;

		ref_reset_hw(idx);

		/* record completed buffer */
		sw_pending_buffers[sw_pending_head++ & (nrbufs - 1)] = buf;
		rmp.rmp_tail++;
	}

	/* check if any buffers are now free */
	uint64_t incr = 1;
	for (size_t i = sw_pending_tail; i != sw_pending_head; i++) {
		if (unlikely(preempt_cede_needed(k)))
			break;

		buf = sw_pending_buffers[i & (nrbufs - 1)];
		if (!buf) {
			sw_pending_tail += incr;
			continue;
		}

		if (get_sw_ref(buf) != DIRECTPATH_NUM_STRIDES) {
			/* stop incrementing the tail once we've hit a hole */
			incr = 0;
			continue;
		}

		ref_reset_sw(buf);
		mempool_free(&directpath_buf_mp, buf);
		sw_pending_buffers[i & (nrbufs - 1)] = NULL;
		sw_pending_tail += incr;
	}

	/* keep cache footprint low */
	if (sw_pending_head == sw_pending_tail)
		sw_pending_head = sw_pending_tail = 0;

	/* refill any free slots in the RX queue */
	while (rmp.rmp_head - rmp.rmp_tail < rmp.wq.cnt) {
		idx = rmp.rmp_head & (rmp.wq.cnt - 1);
		buf = mempool_alloc(&directpath_buf_mp);
		if (unlikely(!buf)) {
			log_warn_ratelimited("out of rx buffers");
			break;
		}

		mlx5_stride_post_buf(&rmp.wq, buf, idx);
		rmp.rmp_head++;
	}

	/* notify NIC of newly posted buffers */
	if (rmp.rmp_head != start_head) {
		udma_to_device_barrier();
		rmp.wq.dbr[0] = htobe32(rmp.rmp_head & 0xffff);
		ACCESS_ONCE(runtime_info->directpath_strides_posted) = rmp.rmp_head;
	}

	/* if completely out of buffers, try reclaiming some from TCP stack */
	if (unlikely(rmp.rmp_head == rmp.rmp_tail)) {
		static uint64_t last_out_of_bufs;
		if (rmp.rmp_head >= last_out_of_bufs) {
			thread_spawn((thread_fn_t)tcp_free_rx_bufs, NULL);
			/* only try this once per full cycle of RQ buffers */
			last_out_of_bufs = rmp.rmp_head + rmp.wq.cnt;
		}
	}

	spin_unlock_np(&rmp.lock);
}


static __noinline void panic_error_cqe(struct mlx5_cqe64 *cqe, uint8_t opcode)
{
	struct mlx5_err_cqe *ecqe = (struct mlx5_err_cqe *)cqe;
	panic("got opcode %02X syndrome %x", opcode, ecqe->syndrome);
}

static inline void print_ip(uint32_t ip)
{
	fprintf(stderr, "%u.%u.%u.%u",
	        (ip >> 24) & 0xff, (ip >> 16) & 0xff,
	        (ip >> 8) & 0xff, ip & 0xff);
}

static struct mbuf *mbuf_fill_cqe(void *dbuf, struct mlx5_cqe64 *cqe,
	                              uint32_t len, uint64_t num_strides)
{
	struct mbuf *m;

	assert_preempt_disabled();
	m = tcache_alloc(perthread_ptr(mbuf_pt));
	if (unlikely(!m)) {
		log_warn_ratelimited("dropping packet; oom");
		return NULL;
	}

	/* copy small packets directly into mbuf */
	if (len <= MBUF_INL_DATA_SZ) {
		void *buf = (void *)m + sizeof(*m);
		memcpy(buf, dbuf + 2, len);
		dec_sw_ref(dbuf, num_strides);
		num_strides = 0;
		dbuf = buf - 2;
	}

	// NIC pads two 0 bytes for alignment of IP headers etc
	mbuf_init(m, dbuf + 2, len, 0);
	m->len = len;
	m->csum_type = mlx5_csum_ok(cqe);
	m->release = directpath_strided_rx_completion;
	m->release_data = num_strides;

	return m;
}


int mlx5_gather_rx_strided(struct mlx5_rxq *v, struct mbuf **ms,
	                       unsigned int budget)
{
	uint8_t opcode;
	uint16_t wqe_idx, stride_idx, stride_cnt, len;
	uint32_t byte_cnt, start_head = v->cq.head, strides_consumed = 0;
	int i, rx_cnt = 0;
	void *buf;
	struct kthread *k;
	struct mlx5_cqe64 *cqe;
	struct mlx5_wq *wq = get_rx_wq(v);

	struct mlx5_cqe64 *cqes[budget];
	void *bufs[budget];
	uint32_t byte_cnts[budget];

	assert(budget <= v->cq.cnt);

	k = getk();

	/* Diagnostic counters */
	static uint64_t total_cqes = 0;
	static uint64_t filler_cqes = 0;
	static uint64_t hw_drops = 0;
	static uint64_t last_diag_print = 0;

	while (rx_cnt < budget && !preempt_cede_needed(k)) {
		cqe = &v->cq.cqes[v->cq.head & (v->cq.cnt - 1)];
		opcode = cqe_status(cqe, v->cq.cnt, v->cq.head);

		if (opcode == MLX5_CQE_INVALID)
			break;

		if (unlikely(opcode != MLX5_CQE_RESP_SEND))
			panic_error_cqe(cqe, opcode);

		/* Debug: Print every valid CQE with RSS hash */
		// static uint64_t cqe_count = 0;
		// if (++cqe_count % 10000 == 0) {
		// 	uint32_t rss_hash = mlx5_get_rss_result(cqe);
		// 	fprintf(stderr, "[CQE POLL] Queue %u: CQE #%lu, RSS hash = 0x%08x\n",
		// 	        k->kthread_idx, cqe_count, rss_hash);
		// 	fflush(stderr);
		// }

		total_cqes++;

		v->cq.head++;
		prefetch(&v->cq.cqes[v->cq.head & (v->cq.cnt - 1)]);

		uint32_t sop_drop = be32toh(cqe->sop_drop_qpn) >> 24;
		hw_drops += sop_drop;
		STAT(RX_HW_DROP) += sop_drop;

		wqe_idx = be16toh(cqe->wqe_id) & (wq->cnt - 1);
		stride_idx = be16toh(cqe->wqe_counter);
		byte_cnt = be32toh(cqe->byte_cnt);
		stride_cnt = (byte_cnt & MLX5_MPRQ_STRIDE_NUM_MASK) >>
				   MLX5_MPRQ_STRIDE_NUM_SHIFT;

		if (shared_rmp_enabled())
			dec_hw_ref(wqe_idx, stride_cnt);
		strides_consumed += stride_cnt;

		buf = load_acquire(&wq->buffers[wqe_idx]);
		if (byte_cnt & MLX5_MPRQ_FILLER_MASK) {
			filler_cqes++;
			dec_sw_ref(buf, stride_cnt);
			continue;
		}

		/* Print diagnostics every 100k CQEs */
		if (total_cqes - last_diag_print >= 10) {
			fprintf(stderr, "[STRIDED DIAG] total_cqes=%lu, filler=%lu (%.1f%%), hw_drops=%lu, rx_cnt_now=%d\n",
			        total_cqes, filler_cqes,
			        total_cqes > 0 ? (100.0 * filler_cqes / total_cqes) : 0.0,
			        hw_drops, rx_cnt);
			fflush(stderr);
			last_diag_print = total_cqes;
		}

		buf += stride_idx * DIRECTPATH_STRIDE_SIZE;
		prefetch(buf);
		bufs[rx_cnt] = buf;
		byte_cnts[rx_cnt] = byte_cnt;
		cqes[rx_cnt++] = cqe;
	}

	/* Port statistics tracking */
	static uint64_t port_stats[15] = {0};
	static uint64_t total_tracked = 0;
	static uint64_t unknown_port_count = 0;

	for (i = 0; i < rx_cnt; i++) {
		cqe = cqes[i];
		buf = bufs[i];

		stride_cnt = (byte_cnts[i] & MLX5_MPRQ_STRIDE_NUM_MASK) >>
				   MLX5_MPRQ_STRIDE_NUM_SHIFT;
		len = byte_cnts[i] & MLX5_MPRQ_LEN_MASK;

		/* Print RSS hash for first packet in batch */
		if (i == 0) {
			static uint64_t total_pkts = 0;
			total_pkts += rx_cnt;
			// if (total_pkts % 10000 < rx_cnt) {
			// 	uint32_t rss_hash = mlx5_get_rss_result(cqe);
			// 	fprintf(stderr, "[RUNTIME STRIDED] Queue %u: RSS hash = 0x%08x (batch %d pkts, total %lu)\n",
			// 	        k->kthread_idx, rss_hash, rx_cnt, total_pkts);
			// 	fflush(stderr);
			// }
		}

		ms[i] = mbuf_fill_cqe(buf, cqe, len, stride_cnt);
		if (unlikely(!ms[i])) {
			// drop remaining packets
			for (; i < rx_cnt; i++)
				dec_sw_ref(bufs[i], (byte_cnts[i] & MLX5_MPRQ_STRIDE_NUM_MASK) >>
				   MLX5_MPRQ_STRIDE_NUM_SHIFT);
			rx_cnt = i;
			break;
		}

		/* Parse destination port for statistics */
		uint16_t dst_port = 0, src_port = 0;
		unsigned char *pkt_data = mbuf_data(ms[i]);
		struct eth_hdr *eth = (struct eth_hdr *)pkt_data;

		if (ntoh16(eth->type) == ETHTYPE_IP) {
			struct ip_hdr *ip = (struct ip_hdr *)(pkt_data + sizeof(struct eth_hdr));
			uint32_t src_ip = ntoh32(ip->saddr);
			uint32_t dst_ip = ntoh32(ip->daddr);
			uint8_t proto = ip->proto;

			if (ip->proto == IPPROTO_UDP) {
				struct udp_hdr *udp = (struct udp_hdr *)((unsigned char *)ip + sizeof(struct ip_hdr));
				src_port = ntoh16(udp->src_port);
				dst_port = ntoh16(udp->dst_port);
			} else if (ip->proto == IPPROTO_TCP) {
				struct tcp_hdr *tcp = (struct tcp_hdr *)((unsigned char *)ip + sizeof(struct ip_hdr));
				src_port = ntoh16(tcp->sport);
				dst_port = ntoh16(tcp->dport);
			}

			/* Track statistics - assume ports are in range [5000, 5014] */
			if (dst_port >= 80 && dst_port < 95) {
				port_stats[dst_port - 80]++;
				total_tracked++;
			} else if (dst_port > 0) {
				unknown_port_count++;
			}

			/* Print 5-tuple for debugging */
			static uint64_t pkt_print_count = 0;
			if (pkt_print_count++ % 1 == 0) {
				fprintf(stderr, "[5-TUPLE] Pkt #%lu: ", pkt_print_count);
				print_ip(src_ip);
				fprintf(stderr, ":%u -> ", src_port);
				print_ip(dst_ip);
				fprintf(stderr, ":%u proto=%u\n", dst_port, proto);
				fflush(stderr);
			}
		}
	}

	/* Print statistics every 100 packets */
	if (total_tracked > 0 && total_tracked % 100 == 0) {
		fprintf(stderr, "\n[PORT STATS STRIDED] Total tracked: %lu, Unknown ports: %lu\n",
		        total_tracked, unknown_port_count);
		for (int j = 0; j < 15; j++) {
			if (port_stats[j] > 0) {
				fprintf(stderr, "  Port %d: %lu packets\n", 80 + j, port_stats[j]);
			}
		}
		fprintf(stderr, "\n");
		fflush(stderr);
	}

	if (start_head != v->cq.head) {
		ACCESS_ONCE(*v->shadow_tail) = v->cq.head;
		v->cq.dbr[0] = htobe32(v->cq.head & 0xffffff);
		k->q_ptrs->directpath_strides_consumed += strides_consumed;
	}

	if (!shared_rmp_enabled()) {
		v->strides_consumed += strides_consumed;
		if (v->strides_consumed >= DIRECTPATH_NUM_STRIDES) {
			mlx5_refill_strided_rxq(v, v->strides_consumed / DIRECTPATH_NUM_STRIDES);
			v->strides_consumed %= DIRECTPATH_NUM_STRIDES;
		}
	}

	putk();

	return rx_cnt;
}

int mlx5_rx_stride_init_bufs(void)
{
	nrbufs = iok.rx_len / DIRECTPATH_STRIDE_MODE_BUF_SZ;
	nrbufs = align_up(nrbufs, CACHE_LINE_SIZE / sizeof(uint16_t));

	if (!is_power_of_two(nrbufs)) {
		log_err("bad directpath buf pool size, want power of two buffer count");
		return -EINVAL;
	}

	sw_refs = calloc(nrbufs * maxks, sizeof(int16_t));
	if (unlikely(!sw_refs))
		return -ENOMEM;

	sw_pending_buffers = calloc(nrbufs, sizeof(void *));
	if (unlikely(!sw_pending_buffers))
		return -ENOMEM;

	if (shared_rmp_enabled()) {
		nr_hw_refs = align_up(DIRECTPATH_STRIDE_RQ_NUM_DESC,
			                  CACHE_LINE_SIZE / sizeof(*hw_refs));
		hw_refs = calloc(nr_hw_refs * maxks, sizeof(*hw_refs));
		if (!hw_refs)
			return -ENOMEM;

		net_ops.trigger_rx_refill = mlx5_refill_strided_rxq_rmp;
	}

	return 0;
}

int mlx5_rx_stride_init_thread(void)
{
	if (!cfg_directpath_strided)
		return 0;

	myk()->q_ptrs->directpath_strides_consumed = 0;

	return 0;
}

int mlx5_rx_stride_init(void)
{
	if (!cfg_directpath_strided || cfg_directpath_external())
		return 0;

	return mlx5_rx_stride_init_bufs();
}

#endif
