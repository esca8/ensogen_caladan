/*
 * rx.c - the receive path for the I/O kernel (network -> runtimes)
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include <base/log.h>
#include <base/debug.h>
#include <iokernel/queue.h>
#include <iokernel/shm.h>

#include "defs.h"
#include "sched.h"

#include <sys/mman.h>

/* Debug flag for RX path - set to 1 to enable detailed packet prints */
#ifndef RX_FS_DEBUG
#define RX_FS_DEBUG 1
#endif

#if RX_FS_DEBUG
#define RX_FS_DBG(fmt, ...) log_info("[RX_FS_DBG] " fmt, ##__VA_ARGS__)
#else
#define RX_FS_DBG(fmt, ...) do { } while (0)
#endif

#define MBUF_CACHE_SIZE 250
#define RX_PREFETCH_STRIDE 2

static union rxq_cmd rx_make_cmd(struct rte_mbuf *buf)
{
	union rxq_cmd cmd;
	uint64_t masked_ol_flags;

	cmd.len = rte_pktmbuf_pkt_len(buf);
	cmd.rxcmd = RX_NET_RECV;
	masked_ol_flags = buf->ol_flags & RTE_MBUF_F_RX_IP_CKSUM_MASK;
	if (masked_ol_flags == RTE_MBUF_F_RX_IP_CKSUM_GOOD)
		cmd.csum_type = CHECKSUM_TYPE_UNNECESSARY;
	else
		cmd.csum_type = CHECKSUM_TYPE_NEEDED;

	return cmd;
}

/**
 * rx_send_to_runtime - enqueues a command to an RXQ for a runtime
 * @p: the runtime's proc structure
 * @hash: the 5-tuple hash for the flow the command is related to
 * @cmd: the command to send
 * @payload: the command payload to send
 *
 * Returns true if the command was enqueued, otherwise a thread is not running
 * and can't be woken or the queue was full.
 */
bool rx_send_to_runtime(struct proc *p, uint32_t hash, uint64_t cmd,
			unsigned long payload)
{
    PRINT_DBG("rx_send_to_runtime | payload = %ld\n", payload); 
	struct thread *th;

	if (likely(sched_threads_active(p) > 0)) {
		/* use the flow table to route to an active thread */
		uint32_t thread_idx = p->flow_tbl[hash % p->thread_count];
		th = &p->threads[thread_idx];
		thread_enable_sched_poll(th);
		bool sent = lrpc_send(&th->rxq, cmd, payload);
		if (!sent) {
			/* Rate limit the entire block (queue full + all depths) */
			static uint64_t last_log_us = 0;
			static uint64_t suppressed = 0;
			uint64_t cur_us = microtime();

			// if (cur_us - last_log_us >= ONE_SECOND) {
			// 	if (suppressed) {
			// 		log_warn("%s:%d %s() suppressed %ld times\n",
			// 			__FILE__, __LINE__, __func__, suppressed);
			// 		suppressed = 0;
			// 	}

            log_warn_ratelimited("LRPC QUEUE FULL: thread_idx=%u core=%u tid=%d active=%d "
                "queue_size=%u send_head=%u send_tail=%u depth=%u "
                "active_threads=%u total_threads=%u hash=0x%x\n",
                thread_idx, th->core, th->tid, th->active,
                th->rxq.size, th->rxq.send_head, th->rxq.send_tail,
                th->rxq.send_head - th->rxq.send_tail,
                sched_threads_active(p), p->thread_count, hash);

				// /* Print all queue depths */
				// log_warn("All queue depths:");
				// for (uint32_t i = 0; i < p->thread_count; i++) {
				// 	struct thread *t = &p->threads[i];
				// 	uint32_t depth = t->rxq.send_head - t->rxq.send_tail;
				// 	log_warn(" [%u]:core=%u,active=%d,depth=%u/%u(%.0f%%)",
				// 		i, t->core, t->active, depth, t->rxq.size,
				// 		100.0 * depth / t->rxq.size);
				// }
				// log_warn("\n");

				// last_log_us = cur_us;
			// } else {
			// 	suppressed++;
			// }
		}
		return sent;
	}

	sched_add_core(p);
	if (unlikely(sched_threads_active(p) == 0)) {
		/* enqueue to an idle thread (to be woken later) */
		th = list_top(&p->idle_threads, struct thread, idle_link);
	} else {
		/* use the flow table to route to an active thread */
		th = &p->threads[p->flow_tbl[hash % p->thread_count]];
	}

	thread_enable_sched_poll(th);
	return lrpc_send(&th->rxq, cmd, payload);
}


/* Software hash fallback when RSS is not available */
static uint32_t compute_software_hash(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	static bool debug_logged = false;

	if (ether_type != ETHTYPE_IP) {
		if (!debug_logged) {
			log_warn("SW_HASH: non-IP packet, ether_type=0x%x (ETHTYPE_IP=0x%x)\n",
				ether_type, ETHTYPE_IP);
			debug_logged = true;
		}
		return 0;
	}

	struct rte_ipv4_hdr *ip_hdr = rte_pktmbuf_mtod_offset(buf,
		struct rte_ipv4_hdr *, sizeof(*eth_hdr));

	uint32_t hash = 0;
	uint32_t src_ip = rte_be_to_cpu_32(ip_hdr->src_addr);
	uint32_t dst_ip = rte_be_to_cpu_32(ip_hdr->dst_addr);
	uint8_t proto = ip_hdr->next_proto_id;

	if (!debug_logged) {
		log_warn("SW_HASH: src=%u.%u.%u.%u dst=%u.%u.%u.%u proto=%u\n",
			(src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff,
			(src_ip >> 8) & 0xff, src_ip & 0xff,
			(dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff,
			(dst_ip >> 8) & 0xff, dst_ip & 0xff, proto);
	}

	/* Simple 5-tuple hash for UDP/TCP */
	if (proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
		struct rte_udp_hdr *l4_hdr = (struct rte_udp_hdr *)
			((uint8_t *)ip_hdr + (ip_hdr->version_ihl & 0x0f) * 4);
		uint16_t src_port = rte_be_to_cpu_16(l4_hdr->src_port);
		uint16_t dst_port = rte_be_to_cpu_16(l4_hdr->dst_port);

		if (!debug_logged) {
			log_warn("SW_HASH: src_port=%u dst_port=%u\n", src_port, dst_port);
		}

		/* Jenkins hash-like mixing */
		hash = src_ip ^ dst_ip ^ src_port ^ (dst_port << 16);
		hash ^= (hash >> 16);
		hash *= 0x85ebca6b;
		hash ^= (hash >> 13);
		hash *= 0xc2b2ae35;
		hash ^= (hash >> 16);

		if (!debug_logged) {
			log_warn("SW_HASH: computed hash=0x%x\n", hash);
			debug_logged = true;
		}
	} else {
		/* Just use IPs for other protocols */
		hash = src_ip ^ dst_ip;
		if (!debug_logged) {
			log_warn("SW_HASH: non-UDP/TCP proto=%u, hash=0x%x\n", proto, hash);
			debug_logged = true;
		}
	}

	return hash;
}

static bool rx_send_pkt_to_runtime(struct proc *p, struct rte_mbuf *buf)
{
    PRINT_DBG("rx_send_pkt_to_runtime\n");
	shmptr_t shmptr;
	union rxq_cmd cmd = rx_make_cmd(buf);
	void *data = rte_pktmbuf_mtod(buf, void *);
	uint32_t hash;
	static bool software_hash_warned = false;

	/* Use RSS hash if avialable, otherwise compute in software */
	if (buf->ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
		hash = buf->hash.rss;
	} 
    // else {
	// 	hash = compute_software_hash(buf);
	// 	if (!software_hash_warned) {
	// 		log_warn("RSS hash not available, using software hash fallback");
	// 		software_hash_warned = true;
	// 	}
	// }
    log_warn_ratelimited("hash: %d", hash); 

	shmptr = ptr_to_shmptr(&dp.ingress_mbuf_region, data, cmd.len);
	if (!rx_send_to_runtime(p, hash, cmd.lrpc_cmd, shmptr))
		return false;

	struct rx_priv_data *pdata = rte_mbuf_to_priv(buf);
	assert(!pdata->owner);
	pdata->owner = p;
	list_add_tail(&p->owned_rx_bufs, &pdata->link);
	assert(pdata == (void *)buf + sizeof(*buf));
	return true;
}

static bool azure_arp_response(struct rte_mbuf *buf)
{
	struct rte_ether_hdr *ptr_mac_hdr;
	struct rte_arp_hdr *arphdr;
	static struct rte_ether_addr azure_eth_addr = {{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}};

	log_debug("sending an arp response");

	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	rte_ether_addr_copy(&ptr_mac_hdr->src_addr, &ptr_mac_hdr->dst_addr);
	rte_ether_addr_copy(&azure_eth_addr, &ptr_mac_hdr->src_addr);

	arphdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr *,
                        sizeof(*ptr_mac_hdr));
	arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
	rte_ether_addr_copy(&azure_eth_addr, &arphdr->arp_data.arp_sha);
	rte_ether_addr_copy(&ptr_mac_hdr->dst_addr, &arphdr->arp_data.arp_tha);
	swapvars(arphdr->arp_data.arp_sip, arphdr->arp_data.arp_tip);

	return rte_eth_tx_burst(dp.port, 0, &buf, 1) == 1;
}

static bool rx_one_pkt(struct rte_mbuf *buf)
{
    PRINT_DBG("rx_one_pkt\n");
	int ret, mark_id;
	struct proc *p;
	struct rte_arp_hdr *arphdr;
	struct rte_ether_hdr *ptr_mac_hdr;
	struct rte_ether_addr *ptr_dst_addr;
	struct rte_ipv4_hdr *iphdr;
	uint16_t ether_type;
	uint32_t dst_ip;

	ptr_mac_hdr = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);
	ptr_dst_addr = &ptr_mac_hdr->dst_addr;

	/* use hardware assisted flow tagging to match packets to procs */
	if (buf->ol_flags & RTE_MBUF_F_RX_FDIR_ID) {
        PRINT_DBG("hardware assisted\n");
		STAT_INC(RX_FLOW_TAG_MATCH, 1);
		mark_id = buf->hash.fdir.hi;
		assert(mark_id >= 0 && mark_id < IOKERNEL_MAX_PROC);
		p = dp.clients_by_id[mark_id];
		if (likely(p)) {
			if (!rx_send_pkt_to_runtime(p, buf)) {
				STAT_INC(RX_UNICAST_FAIL, 1);
				goto fail_free;
			}
			return true;
		}
	}

	PRINT_DBG("rx: rx packet with MAC %02" PRIx8 " %02" PRIx8 " %02"
		  PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
		  ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
		  ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
		  ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);

	ether_type = rte_be_to_cpu_16(ptr_mac_hdr->ether_type);

	if (likely(ether_type == ETHTYPE_IP)) {
        PRINT_DBG("rx.c: ether_type == ETHTYPE_IP\n");
		iphdr = rte_pktmbuf_mtod_offset(buf, struct rte_ipv4_hdr *,
			sizeof(*ptr_mac_hdr));
		dst_ip = rte_be_to_cpu_32(iphdr->dst_addr);

		/* Debug: Print destination IP:port */
		uint8_t proto = iphdr->next_proto_id;
		uint16_t dst_port = 0;
		uint16_t src_port = 0;
		uint32_t src_ip = rte_be_to_cpu_32(iphdr->src_addr);
		uint8_t ip_version = (iphdr->version_ihl >> 4) & 0xf;
		if (proto == IPPROTO_UDP || proto == IPPROTO_TCP) {
			struct rte_udp_hdr *l4_hdr = (struct rte_udp_hdr *)
				((uint8_t *)iphdr + ((iphdr->version_ihl & 0x0f) * 4));
			dst_port = rte_be_to_cpu_16(l4_hdr->dst_port);
			src_port = rte_be_to_cpu_16(l4_hdr->src_port);
		}
		log_warn_ratelimited("RX_PKT: dst=%u.%u.%u.%u:%u proto=%u len=%u",
			(dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff,
			(dst_ip >> 8) & 0xff, dst_ip & 0xff,
			dst_port, proto, buf->pkt_len);

		/* Detailed packet header for flow steering debug */
		RX_FS_DBG("=== PKT ARRIVED AT IOKERNEL (should NOT happen in FS mode!) ===");
		RX_FS_DBG("  ethertype=0x%04x (expected 0x%04x for IPv4)", ether_type, ETHTYPE_IP);
		RX_FS_DBG("  ip_version=%u (expected 4)", ip_version);
		RX_FS_DBG("  src_ip=%u.%u.%u.%u (0x%08x)",
		          (src_ip >> 24) & 0xff, (src_ip >> 16) & 0xff,
		          (src_ip >> 8) & 0xff, src_ip & 0xff, src_ip);
		RX_FS_DBG("  dst_ip=%u.%u.%u.%u (0x%08x)",
		          (dst_ip >> 24) & 0xff, (dst_ip >> 16) & 0xff,
		          (dst_ip >> 8) & 0xff, dst_ip & 0xff, dst_ip);
		RX_FS_DBG("  ip_protocol=%u (%s)", proto,
		          proto == IPPROTO_TCP ? "TCP" : proto == IPPROTO_UDP ? "UDP" : "OTHER");
		RX_FS_DBG("  src_port=%u, dst_port=%u", src_port, dst_port);
		RX_FS_DBG("  pkt_len=%u", buf->pkt_len);
		RX_FS_DBG("  => Compare dst_ip above with runtime IP in FS rules!");

		if (unlikely(!(buf->ol_flags & RTE_MBUF_F_RX_RSS_HASH)))
			STAT_INC(RX_HASH_MISSING, 1);
	} else if (ether_type == ETHTYPE_ARP) {
        PRINT_DBG("rx.c: ether_type == ETHTYPE_ARP\n"); 
		arphdr = rte_pktmbuf_mtod_offset(buf, struct rte_arp_hdr *,
			sizeof(*ptr_mac_hdr));
		dst_ip = rte_be_to_cpu_32(arphdr->arp_data.arp_tip);

		// Azure's faked ARP replies always go to the default NIC
		// address, so broadcast them to all runtimes.
		if (cfg.azure_arp_mode &&
		    arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
			bool success;
			int n_sent = 0;
			for (int i = 0; i < dp.nr_clients; i++) {
				success = rx_send_pkt_to_runtime(dp.clients[i], buf);
				if (success) {
					n_sent++;
				} else {
					STAT_INC(RX_BROADCAST_FAIL, 1);
					log_debug_ratelimited("rx: failed to enqueue broadcast "
					                      "packet to runtime");
				}
			}
			if (n_sent == 0)
				rte_pktmbuf_free(buf);
			else
				rte_mbuf_refcnt_update(buf, n_sent - 1);
			return (n_sent > 0);
		}
	} else {
		log_debug("unrecognized ether type");
		goto fail_free;
	}

	/* lookup runtime by IP in hash table */
	ret = rte_hash_lookup_data(dp.ip_to_proc, &dst_ip, (void **)&p);
	if (unlikely(ret < 0)) {

		if (cfg.azure_arp_mode && ether_type == ETHTYPE_ARP &&
		    arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) &&
		    azure_arp_response(buf))
			return false;  /* ARP response sent, but not to runtime */

		STAT_INC(RX_UNREGISTERED_MAC, 1);
		goto fail_free;
	}

	if (!rx_send_pkt_to_runtime(p, buf)) {
		STAT_INC(RX_UNICAST_FAIL, 1);
		goto fail_free;
	}

	if (unlikely(p->has_directpath)) {
		if (!cfg.azure_arp_mode && ether_type == ETHTYPE_IP)
			log_warn_ratelimited("delivering an IP packet to a directpath runtime");
	}

	return true;

fail_free:
	/* anything else */
	log_debug("rx: unhandled packet with MAC %x %x %x %x %x %x",
		 ptr_dst_addr->addr_bytes[0], ptr_dst_addr->addr_bytes[1],
		 ptr_dst_addr->addr_bytes[2], ptr_dst_addr->addr_bytes[3],
		 ptr_dst_addr->addr_bytes[4], ptr_dst_addr->addr_bytes[5]);
	rte_pktmbuf_free(buf);
	STAT_INC(RX_UNHANDLED, 1);
	return false;
}

void rx_loopback(struct rte_mbuf **src_bufs, int n_bufs)
{
	int i, ret;
	struct proc *p;
	struct rte_mbuf *rx_bufs[n_bufs];
	struct tx_pktmbuf_priv *priv;

	ret = rte_pktmbuf_alloc_bulk(dp.rx_mbuf_pool, rx_bufs, n_bufs);
	if (unlikely(ret)) {
		log_warn_ratelimited("Couldn't allocate buffers for loopback");
		rte_pktmbuf_free_bulk(src_bufs, n_bufs);
		return;
	}

	/* Do IP lookups using runtime-provided hint */
	for (i = 0; i < n_bufs; i++) {
		priv = rte_mbuf_to_priv(src_bufs[i]);
		if (!priv->dst_ip)
			continue;

		ret = rte_hash_lookup_data(dp.ip_to_proc, &priv->dst_ip,
			                   (void **)&p);
		priv->dst_ip = 0;
		if (likely(ret >= 0)) {
			src_bufs[i]->ol_flags |= RTE_MBUF_F_RX_FDIR_ID;
			src_bufs[i]->hash.fdir.hi = p->uniqid;
		}
	}

	copy_batch(src_bufs, rx_bufs, n_bufs, rx_one_pkt);
}

/*
 * Process a batch of incoming packets.
 */
bool rx_burst(void)
{
	struct rte_mbuf *bufs[IOKERNEL_RX_BURST_SIZE];
	uint16_t nb_rx, i;
	static uint64_t total_rx_pkts = 0;
	static uint64_t total_sent_to_runtime = 0;
	uint16_t sent_this_burst = 0;

	/* retrieve packets from NIC queue */
	nb_rx = rte_eth_rx_burst(dp.port, 0, bufs, IOKERNEL_RX_BURST_SIZE);
	STAT_INC(RX_PULLED, nb_rx);

	total_rx_pkts += nb_rx;
	if (total_rx_pkts > 0 && total_rx_pkts % 50000 < nb_rx) {
		fprintf(stderr, "[IOKERNEL RX] Received %lu packets from NIC DPDK queue\n", total_rx_pkts);
		fflush(stderr);
	}

	if (nb_rx > 0) {
		PRINT_DBG("rx: received %d packets on port %d\n", nb_rx, dp.port);
    } else {
        // log_warn_ratelimited("rx: received no packets on port %d\n", dp.port);
    }
	for (i = 0; i < nb_rx; i++) {
		if (i + RX_PREFETCH_STRIDE < nb_rx) {
			prefetch(rte_pktmbuf_mtod(bufs[i + RX_PREFETCH_STRIDE],
				 char *));
		}
		bool sent = rx_one_pkt(bufs[i]);
		if (sent) sent_this_burst++;
	}

	total_rx_pkts += nb_rx;
	total_sent_to_runtime += sent_this_burst;
	// if (nb_rx > 0) {
	// 	log_info("IOKERNEL BURST: received=%u sent_to_runtime=%u (total_rx=%lu total_sent=%lu)",
	// 		nb_rx, sent_this_burst, total_rx_pkts, total_sent_to_runtime);
	// }

	/* Periodically check for NIC drops */
	// static uint64_t last_check_rx = 0;
	// if (total_rx_pkts - last_check_rx > 1000000) {
	// 	last_check_rx = total_rx_pkts;
	// 	struct rte_eth_stats stats;
	// 	rte_eth_stats_get(dp.port, &stats);
	// 	log_warn_ratelimited("NIC STATS: ipackets=%lu ierrors=%lu imissed=%lu rx_nombuf=%lu",
	// 		stats.ipackets, stats.ierrors, stats.imissed, stats.rx_nombuf);
	// }

	return nb_rx > 0;
}

/*
 * Callback to unmap the shared memory used by a mempool when destroying it.
 */
static void rx_mempool_memchunk_free(struct rte_mempool_memhdr *memhdr,
		void *opaque)
{
	mem_unmap_shm(opaque);
}

/*
 * Zero out private data for a packet
 */

static void rx_pktmbuf_priv_init(struct rte_mempool *mp, void *opaque,
				 void *obj, unsigned obj_idx)
{
	struct rte_mbuf *buf = obj;
	struct rx_priv_data *data = rte_mbuf_to_priv(buf);
	memset(data, 0, sizeof(*data));
}

/*
 * Create and initialize a packet mbuf pool in shared memory, based on
 * rte_pktmbuf_pool_create.
 */
static struct rte_mempool *rx_pktmbuf_pool_create_in_shm(const char *name,
		unsigned n, unsigned cache_size, uint16_t priv_size,
		uint16_t data_room_size, int socket_id)
{
	struct rte_mempool_objsz objsz;
	unsigned elt_size;
	struct rte_pktmbuf_pool_private mbp_priv = {0};
	struct rte_mempool *mp;
	int ret;
	size_t pg_size, pg_shift, min_chunk_size, align, len;
	void *shbuf;

	/* create rte_mempool */
	if (RTE_ALIGN(priv_size, RTE_MBUF_PRIV_ALIGN) != priv_size) {
		log_err("rx: mbuf priv_size=%u is not aligned", priv_size);
		goto fail;
	}
	elt_size = sizeof(struct rte_mbuf) + (unsigned) priv_size
			+ (unsigned) data_room_size;
	mbp_priv.mbuf_data_room_size = data_room_size;
	mbp_priv.mbuf_priv_size = priv_size;

	mp = rte_mempool_create_empty(name, n, elt_size, cache_size,
			sizeof(struct rte_pktmbuf_pool_private), socket_id, 0);
	if (mp == NULL)
		goto fail;

	ret = rte_mempool_set_ops_byname(mp, RTE_MBUF_DEFAULT_MEMPOOL_OPS, NULL);
	if (ret != 0) {
		log_err("rx: error setting mempool handler");
		goto fail_free_mempool;
	}
	rte_pktmbuf_pool_init(mp, &mbp_priv);

	/* check necessary size and map shared memory */
	pg_size = PGSIZE_2MB;
	pg_shift = rte_bsf32(pg_size);
	len = rte_mempool_ops_calc_mem_size(mp, n, pg_shift, &min_chunk_size, &align);
	if (len > INGRESS_MBUF_SHM_SIZE) {
		log_err("rx: shared memory is too small for number of mbufs");
		goto fail_free_mempool;
	}

	shbuf = dp.ingress_mbuf_region.base;
	len = align_up(len, pg_size);

	/* truncate the recorded region len */
	dp.ingress_mbuf_region.len = len;

	ret = do_dpdk_dma_map(shbuf, len, pg_size, NULL);
	if (ret)
		goto fail_free_mempool;

	/* populate mempool using shared memory */
	ret = rte_mempool_populate_virt(mp, shbuf, len, pg_size,
			rx_mempool_memchunk_free, shbuf);
	if (ret < 0) {
		log_err("rx: error populating mempool %d", ret);
		goto fail_unmap_dma;
	}

	rte_mempool_obj_iter(mp, rte_pktmbuf_init, NULL);
	rte_mempool_obj_iter(mp, rx_pktmbuf_priv_init, NULL);

	BUG_ON(rte_mempool_calc_obj_size(elt_size, 0, &objsz) != RX_ELT_SIZE);
	BUG_ON(objsz.header_size != RX_OBJ_HDR_SZ);

	return mp;

fail_unmap_dma:
	do_dpdk_dma_unmap(shbuf, len, pg_size, NULL);
fail_free_mempool:
	rte_mempool_free(mp);
fail:
	log_err("rx: couldn't create pktmbuf pool %s", name);
	return NULL;
}

/*
 * Initialize rx state.
 */
int rx_init(void)
{
	if (cfg.vfio_directpath)
		return 0;

	/* create a mempool in shared memory to hold the rx mbufs */
	dp.rx_mbuf_pool = rx_pktmbuf_pool_create_in_shm("RX_MBUF_POOL",
			IOKERNEL_NUM_MBUFS, MBUF_CACHE_SIZE,
			sizeof(struct rx_priv_data), RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());

	if (dp.rx_mbuf_pool == NULL) {
		log_err("rx: couldn't create rx mbuf pool");
		return -1;
	}

	return 0;
}
