
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

/* batch-size histogram seen by mlx5_gather_rx (defined in mlx5_rxtx.c); size = RUNTIME_RX_BATCH_SIZE + 1 */
extern uint64_t rxlat_burst_hist[33];

/* start the runtime STAT responder on port 40 (runtime/stat.c) */
extern int stat_init_late(void);
