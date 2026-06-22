/*
 * stat.c - support for statistics and counters
 */

#include <string.h>
#include <stdio.h>

#include <base/stddef.h>
#include <base/log.h>
#include <base/time.h>
#include <base/tcache.h>
#include <base/thread.h>
#include <runtime/thread.h>
#include <runtime/timer.h>
#include <runtime/udp.h>
#include <runtime/tcp.h>

#include "defs.h"

/* port 40 is permanently reserved, so should be fine for now */
#define STAT_PORT	40

/* periodic stat dumper: emit per-kthread + aggregate stats to stdout
 * (via log_info) every N microseconds. Output lands in the runtime's stdout
 * which the experiment harness captures as runtime.log.
 *
 * Disabled by default to avoid log_info overhead on the hot path. Apps
 * enable via runtime_set_log_runtime_stats(true) (declared in
 * inc/runtime/runtime.h, exposed to Rust via the shenango bindings). */
#define STAT_DUMP_INTERVAL_US	(1000 * 1000)  /* 1 second */

static bool log_runtime_stats_enabled = false;

void runtime_set_log_runtime_stats(bool enabled)
{
	log_runtime_stats_enabled = enabled;
}

static const char *stat_names[] = {
	/* scheduler counters */
	"reschedules",
	"sched_cycles",
	"program_cycles",
	"threads_stolen",
	"softirqs_stolen",
	"softirqs_local",
	"parks",
	"preemptions",
	"core_migrations",
	"local_runs",
	"remote_runs",
	"local_wakes",
	"remote_wakes",
	"rq_overflow",

	/* network stack counters */
	"rx_bytes",
	"rx_packets",
	"tx_bytes",
	"tx_packets",
	"drops",
	"rx_tcp_in_order",
	"rx_tcp_out_of_order",
	"rx_tcp_text_cycles",
	"txq_overflow",

	/* directpath counters */
	"flow_steering_cycles",
	"rx_hw_drop",

};

static const char *tc_stat_names[] = {
	"mag_free",
	"mag_alloc",
	"pool_alloc",
	"pool_free"
};


/* must correspond exactly to STAT_* enum definitions in defs.h */
BUILD_ASSERT(ARRAY_SIZE(stat_names) == STAT_NR);

static int append_stat(char **pos, char *end, const char *name, uint64_t val)
{
	int ret = snprintf(*pos, end - *pos, "%s:%ld,", name, val);
	if (ret < 0)
		return -EINVAL;
	if (ret >= end - *pos)
		return -E2BIG;
	*pos += ret;
	return 0;
}

static ssize_t stat_write_buf(char *buf, size_t len)
{
	uint64_t stats[STAT_NR], tc_stats[4];
	uint64_t per_k[STAT_NR];
	uint64_t in_flight_cycles;
	char keybuf[64];
	struct kthread *k;
	char *pos = buf, *end = buf + len;
	int i, j, ret;

	memset(stats, 0, sizeof(stats));
	memset(tc_stats, 0, sizeof(tc_stats));

	/* per-kthread emit + accumulate totals */
	for (i = 0; i < maxks; i++) {
		k = &ks[i];
		for (j = 0; j < STAT_NR; j++) {
			per_k[j] = k->stats[j];
			stats[j] += per_k[j];
		}

		/* if a uthread is currently running on this kthread, add its
		 * in-flight cycles to PROGRAM_CYCLES (both per-kthread and total) */
		in_flight_cycles = 0;
		if ((ACCESS_ONCE(k->q_ptrs->rcu_gen) & 0x1) != 0) {
			in_flight_cycles = rdtsc() -
				ACCESS_ONCE(k->q_ptrs->run_start_tsc);
			per_k[STAT_PROGRAM_CYCLES] += in_flight_cycles;
			stats[STAT_PROGRAM_CYCLES] += in_flight_cycles;
		}

		for (j = 0; j < STAT_NR; j++) {
			ret = snprintf(keybuf, sizeof(keybuf),
				       "k%d_%s", i, stat_names[j]);
			if (ret < 0 || (size_t)ret >= sizeof(keybuf))
				return -E2BIG;
			ret = append_stat(&pos, end, keybuf, per_k[j]);
			if (ret)
				return ret;
		}
	}

	for_each_thread(i) {
		tc_stats[0] += perthread_get_remote(mag_free, i);
		tc_stats[1] += perthread_get_remote(mag_alloc, i);
		tc_stats[2] += perthread_get_remote(pool_alloc, i);
		tc_stats[3] += perthread_get_remote(pool_free, i);
	}

	/* global totals (kept for backwards compat) */
	for (j = 0; j < STAT_NR; j++) {
		ret = append_stat(&pos, end, stat_names[j], stats[j]);
		if (ret)
			return ret;
	}

	for (j = 0; j < ARRAY_SIZE(tc_stats); j++) {
		ret = append_stat(&pos, end, tc_stat_names[j], tc_stats[j]);
		if (ret)
			return ret;
	}

	ret = append_stat(&pos, end, "maxks", maxks);
	if (ret)
		return ret;

	ret = append_stat(&pos, end, "cycles_per_us", cycles_per_us);
	if (ret)
		return ret;

	ret = append_stat(&pos, end, "tsc", rdtsc());
	if (ret)
		return ret;

	pos[-1] = '\0'; /* clip off last ',' */
	return pos - buf;
}

static void stat_tcp_worker(void *arg)
{
	struct {
		size_t resp_size;
		char buf[65535];
	} resp;
	ssize_t ret, len, done;
	tcpconn_t *c = arg;

	while (true) {
		ret = tcp_read(c, resp.buf, 1);
		if (ret <= 0)
			goto done;

		len = stat_write_buf(resp.buf, sizeof(resp.buf));
		if (len < 0) {
			WARN();
			continue;
		}

		/* start with the size of the response body */
		resp.resp_size = len;

		done = 0;
		do {
			ret = tcp_write(c, (char *)&resp + done, sizeof(size_t) + len - done);
			if (ret < 0) {
				WARN_ON(ret != -EPIPE && ret != -ECONNRESET);
				goto done;
			}
			done += ret;
		} while (done < sizeof(size_t) + len);
	}

done:
	tcp_close(c);
	return;
}

static void stat_tcp_server(void *arg)
{
	struct netaddr laddr;
	tcpconn_t *c;
	tcpqueue_t *q;
	int ret;

	laddr.ip = 0;
	laddr.port = STAT_PORT;

	ret = tcp_listen(laddr, 4096, &q);
	BUG_ON(ret);

	while (true) {
		ret = tcp_accept(q, &c);
		BUG_ON(ret);
		ret = thread_spawn(stat_tcp_worker, c);
		WARN_ON(ret);
	}
}

static void stat_worker_udp(void *arg)
{
	const size_t cmd_len = strlen("stat");
	size_t payload_size = udp_get_payload_size();
	char buf[payload_size];
	struct netaddr laddr, raddr;
	udpconn_t *c;
	ssize_t ret, len;

	laddr.ip = 0;
	laddr.port = STAT_PORT;

	ret = udp_listen(laddr, &c);
	if (ret) {
		log_err("stat: udp_listen failed, ret = %ld", ret);
		return;
	}

	while (true) {
		ret = udp_read_from(c, buf, payload_size, &raddr);
		if (ret < cmd_len)
			continue;
		if (strncmp(buf, "stat", cmd_len) != 0)
			continue;

		len = stat_write_buf(buf, payload_size);
		if (len < 0) {
			log_err("stat: couldn't generate stat buffer");
			continue;
		}
		assert(len <= payload_size);

		ret = udp_write_to(c, buf, len, &raddr);
		WARN_ON(ret != len);
	}
}

/* Write one kthread's stat slice into `buf`. Format:
 *   k0_reschedules:N,k0_sched_cycles:N,...,k0_rx_hw_drop:N
 * Returns the length written (excluding NUL), or negative on error. */
static ssize_t stat_format_kthread(char *buf, size_t len, int idx)
{
	struct kthread *k = &ks[idx];
	uint64_t per_k[STAT_NR];
	uint64_t in_flight_cycles;
	char keybuf[64];
	char *pos = buf, *end = buf + len;
	int j, ret;

	for (j = 0; j < STAT_NR; j++)
		per_k[j] = k->stats[j];

	if ((ACCESS_ONCE(k->q_ptrs->rcu_gen) & 0x1) != 0) {
		in_flight_cycles = rdtsc() -
			ACCESS_ONCE(k->q_ptrs->run_start_tsc);
		per_k[STAT_PROGRAM_CYCLES] += in_flight_cycles;
	}

	for (j = 0; j < STAT_NR; j++) {
		ret = snprintf(keybuf, sizeof(keybuf),
			       "k%d_%s", idx, stat_names[j]);
		if (ret < 0 || (size_t)ret >= sizeof(keybuf))
			return -E2BIG;
		ret = append_stat(&pos, end, keybuf, per_k[j]);
		if (ret)
			return ret;
	}

	if (pos > buf)
		pos[-1] = '\0'; /* clip trailing comma */
	return pos - buf;
}

/* Write the aggregate stat slice into `buf`. Format:
 *   reschedules:N,sched_cycles:N,...,mag_free:N,...,maxks:N,cycles_per_us:N,tsc:N
 * Returns the length written (excluding NUL), or negative on error. */
static ssize_t stat_format_aggregate(char *buf, size_t len)
{
	uint64_t stats[STAT_NR], tc_stats[4];
	uint64_t in_flight_cycles;
	struct kthread *k;
	char *pos = buf, *end = buf + len;
	int i, j, ret;

	memset(stats, 0, sizeof(stats));
	memset(tc_stats, 0, sizeof(tc_stats));

	for (i = 0; i < maxks; i++) {
		k = &ks[i];
		for (j = 0; j < STAT_NR; j++)
			stats[j] += k->stats[j];

		if ((ACCESS_ONCE(k->q_ptrs->rcu_gen) & 0x1) != 0) {
			in_flight_cycles = rdtsc() -
				ACCESS_ONCE(k->q_ptrs->run_start_tsc);
			stats[STAT_PROGRAM_CYCLES] += in_flight_cycles;
		}
	}

	for_each_thread(i) {
		tc_stats[0] += perthread_get_remote(mag_free, i);
		tc_stats[1] += perthread_get_remote(mag_alloc, i);
		tc_stats[2] += perthread_get_remote(pool_alloc, i);
		tc_stats[3] += perthread_get_remote(pool_free, i);
	}

	for (j = 0; j < STAT_NR; j++) {
		ret = append_stat(&pos, end, stat_names[j], stats[j]);
		if (ret)
			return ret;
	}

	for (j = 0; j < ARRAY_SIZE(tc_stats); j++) {
		ret = append_stat(&pos, end, tc_stat_names[j], tc_stats[j]);
		if (ret)
			return ret;
	}

	ret = append_stat(&pos, end, "maxks", maxks);
	if (ret) return ret;

	ret = append_stat(&pos, end, "cycles_per_us", cycles_per_us);
	if (ret) return ret;

	ret = append_stat(&pos, end, "tsc", rdtsc());
	if (ret) return ret;

	if (pos > buf)
		pos[-1] = '\0';
	return pos - buf;
}

/* Periodic dumper: emits one `runtime_stats k=NN <slice>` line per kthread
 * plus one `runtime_stats agg <slice>` line, every STAT_DUMP_INTERVAL_US.
 * Slices fit well within Caladan's MAX_LOG_LEN (4096) at typical kthread
 * counts; if a slice ever overflows, the line is dropped with a warning. */
static void stat_periodic_dumper(void *arg)
{
	char buf[3072];
	ssize_t len;
	int i;

	while (true) {
		timer_sleep(STAT_DUMP_INTERVAL_US);

		if (!ACCESS_ONCE(log_runtime_stats_enabled))
			continue;

		for (i = 0; i < maxks; i++) {
			len = stat_format_kthread(buf, sizeof(buf), i);
			if (len < 0) {
				log_warn_ratelimited(
					"stat: kthread %d slice too big (%ld)",
					i, len);
				continue;
			}
			log_info("runtime_stats k=%d %s", i, buf);
		}

		len = stat_format_aggregate(buf, sizeof(buf));
		if (len < 0) {
			log_warn_ratelimited(
				"stat: aggregate slice too big (%ld)", len);
			continue;
		}
		log_info("runtime_stats agg %s", buf);
	}
}

/**
 * stat_init_late - starts the stat responder thread
 *
 * Returns 0 if succesful.
 */
int stat_init_late(void)
{
	int ret;

	ret = thread_spawn(stat_tcp_server, NULL);
	if (ret)
		return ret;

	ret = thread_spawn(stat_worker_udp, NULL);
	if (ret)
		return ret;

	return thread_spawn(stat_periodic_dumper, NULL);
}
