package burp.openapirbactester;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Executes an N endpoints × M identities cross-product of HTTP requests on a background
 * thread pool, streaming per-cell results to a listener as they complete. Supports
 * cancellation mid-run.
 *
 * Not thread-safe to call {@link #run} concurrently on the same instance; use a fresh
 * runner per comparison. {@link #shutdown} releases the pool when done.
 */
public class RbacRunner {

    public interface Listener {
        /**
         * Called on a worker thread whenever a single cell completes.
         *
         * @param row    endpoint row index
         * @param col    identity column index
         * @param result parsed cell outcome (status, size, elapsed)
         * @param raw    optional raw response for click-through (Montoya HttpRequestResponse
         *               in production; {@code null} in tests)
         */
        void onCellComplete(int row, int col, RbacCellResult result, Object raw);

        /** Called on a worker thread when every cell has resolved (or cancel took effect). */
        void onFinished(boolean wasCancelled, int completedCount, int totalCount);
    }

    private final RbacHttpSender sender;
    private final ExecutorService executor;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicBoolean running = new AtomicBoolean(false);

    public RbacRunner(RbacHttpSender sender, int concurrency) {
        this.sender = Objects.requireNonNull(sender, "sender");
        if (concurrency < 1) throw new IllegalArgumentException("concurrency must be >= 1");
        this.executor = Executors.newFixedThreadPool(concurrency, r -> {
            Thread t = new Thread(r, "rbac-tester-worker");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Starts running the cross-product. Returns immediately — results arrive via
     * {@code listener}. Each (endpoint, identity) pair becomes one task on the pool.
     *
     * @param endpoints  ordered rows
     * @param identities ordered columns — priority ascending (least-privileged first)
     * @param listener   callback for per-cell completion and final finish
     */
    public void run(List<ApiEndpoint> endpoints, List<Identity> identities, Listener listener) {
        Objects.requireNonNull(endpoints, "endpoints");
        Objects.requireNonNull(identities, "identities");
        Objects.requireNonNull(listener, "listener");
        if (!running.compareAndSet(false, true)) {
            throw new IllegalStateException("Runner already started");
        }
        cancelled.set(false);

        int total = endpoints.size() * identities.size();
        if (total == 0) {
            listener.onFinished(false, 0, 0);
            return;
        }

        AtomicInteger completed = new AtomicInteger(0);
        List<Runnable> tasks = new ArrayList<>(total);
        for (int row = 0; row < endpoints.size(); row++) {
            for (int col = 0; col < identities.size(); col++) {
                final int r = row;
                final int c = col;
                final ApiEndpoint ep = endpoints.get(row);
                final Identity id = identities.get(col);
                tasks.add(() -> {
                    if (cancelled.get()) {
                        int done = completed.incrementAndGet();
                        if (done == total) listener.onFinished(true, done, total);
                        return;
                    }
                    RbacCellResult cell;
                    Object raw = null;
                    try {
                        RbacHttpSender.SendResult sr = sender.send(ep, id.authConfig(), id.baseUrlOverride());
                        if (sr == null || sr.cell() == null) {
                            cell = RbacCellResult.error("null result from sender", 0);
                        } else {
                            cell = sr.cell();
                            raw = sr.raw();
                        }
                    } catch (Throwable t) {
                        cell = RbacCellResult.error(t.getClass().getSimpleName() + ": " + t.getMessage(), 0);
                    }
                    listener.onCellComplete(r, c, cell, raw);
                    int done = completed.incrementAndGet();
                    if (done == total) listener.onFinished(cancelled.get(), done, total);
                });
            }
        }
        for (Runnable task : tasks) executor.submit(task);
    }

    /** Signals in-flight tasks to skip their HTTP send. Tasks already dispatched will finish. */
    public void cancel() {
        cancelled.set(true);
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    /**
     * Cancels and hard-stops the pool without waiting. For extension unload, where several
     * runners may be live and a per-runner wait would add up on the caller's thread.
     */
    public void abort() {
        cancelled.set(true);
        executor.shutdownNow();
    }

    /** Releases the worker pool. Waits briefly for in-flight tasks, then hard-stops. */
    public void shutdown() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(3, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
