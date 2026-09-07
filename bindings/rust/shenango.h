
#include <stdbool.h>

#include <base/assert.h>
#include <base/init.h>
#include <base/lock.h>
#include <base/log.h>
#include <base/slab.h>
#include <base/time.h>
#include <base/tcache.h>

#include <runtime/preempt.h>
#include <runtime/runtime.h>
#include <runtime/smalloc.h>
#include <runtime/storage.h>
#include <runtime/sync.h>
#include <runtime/tcp.h>
#include <runtime/thread.h>
#include <runtime/timer.h>
#include <runtime/udp.h>

/* per-kthread batch-size histogram seen by mlx5_gather_rx (defined in mlx5_rxtx.c); NCPU x (RUNTIME_RX_BATCH_SIZE + 1) */
extern uint64_t rxlat_burst_hist[256][33];

/* per-kthread runqueue depth after a batch is delivered (mlx5_rxtx.c); index 32 = >= 32 */
extern uint64_t rxlat_rq_hist[256][33];

/* fill buf with per-kthread runtime STAT counters (runtime/stat.c) */
extern ssize_t stat_write_buf(char *buf, size_t len);
