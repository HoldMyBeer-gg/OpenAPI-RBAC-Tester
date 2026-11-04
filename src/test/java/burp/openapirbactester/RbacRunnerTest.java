package burp.openapirbactester;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RbacRunnerTest {

    private static ApiEndpoint endpoint(int i, String path) {
        return new ApiEndpoint(i, "https", "GET", "https://api.test.com", path, List.of(), "");
    }

    private static Identity identity(String name) {
        return Identity.empty(name);
    }

    private static class RecordingListener implements RbacRunner.Listener {
        final List<int[]> cells = new ArrayList<>();
        final AtomicInteger finishedCount = new AtomicInteger(-1);
        final AtomicInteger finishedTotal = new AtomicInteger(-1);
        volatile boolean wasCancelled;
        final CountDownLatch finishLatch = new CountDownLatch(1);

        @Override
        public synchronized void onCellComplete(int row, int col, RbacCellResult result, Object raw) {
            cells.add(new int[]{row, col});
        }

        @Override
        public void onFinished(boolean wasCancelled, int completed, int total) {
            this.wasCancelled = wasCancelled;
            this.finishedCount.set(completed);
            this.finishedTotal.set(total);
            finishLatch.countDown();
        }
    }

    @Test
    void run_fullCrossProduct_everyCellReported() throws Exception {
        var endpoints = List.of(endpoint(1, "/a"), endpoint(2, "/b"));
        var identities = List.of(identity("anon"), identity("user"), identity("admin"));

        RbacHttpSender sender = (ep, auth, base) ->
                new RbacHttpSender.SendResult(RbacCellResult.ok(200, 10, 5), null);

        RbacRunner runner = new RbacRunner(sender, 4);
        var listener = new RecordingListener();
        runner.run(endpoints, identities, listener);
        assertTrue(listener.finishLatch.await(5, TimeUnit.SECONDS), "runner should finish");
        assertEquals(6, listener.cells.size(), "2 endpoints × 3 identities = 6 cells");
        assertEquals(6, listener.finishedCount.get());
        assertEquals(6, listener.finishedTotal.get());
        assertFalse(listener.wasCancelled);
        runner.shutdown();
    }

    @Test
    void run_emptyInput_finishesImmediately() throws Exception {
        RbacRunner runner = new RbacRunner((ep, a, b) -> null, 2);
        var listener = new RecordingListener();
        runner.run(List.of(), List.of(), listener);
        assertTrue(listener.finishLatch.await(1, TimeUnit.SECONDS));
        assertEquals(0, listener.cells.size());
        assertEquals(0, listener.finishedTotal.get());
        runner.shutdown();
    }

    @Test
    void run_senderThrows_cellMarkedAsError() throws Exception {
        RbacHttpSender sender = (ep, a, b) -> { throw new RuntimeException("nope"); };
        RbacRunner runner = new RbacRunner(sender, 2);
        var captured = new ArrayList<RbacCellResult>();
        CountDownLatch done = new CountDownLatch(1);
        runner.run(
                List.of(endpoint(1, "/a")),
                List.of(identity("x")),
                new RbacRunner.Listener() {
                    @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {
                        captured.add(result);
                    }
                    @Override public void onFinished(boolean cancelled, int completed, int total) {
                        done.countDown();
                    }
                });
        assertTrue(done.await(2, TimeUnit.SECONDS));
        assertEquals(1, captured.size());
        assertTrue(captured.get(0).isError());
        assertTrue(captured.get(0).errorMessage().contains("nope"));
        runner.shutdown();
    }

    @Test
    void run_senderReturnsNull_cellMarkedAsError() throws Exception {
        RbacHttpSender sender = (ep, a, b) -> null;
        RbacRunner runner = new RbacRunner(sender, 1);
        var captured = new ArrayList<RbacCellResult>();
        CountDownLatch done = new CountDownLatch(1);
        runner.run(
                List.of(endpoint(1, "/a")),
                List.of(identity("x")),
                new RbacRunner.Listener() {
                    @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {
                        captured.add(result);
                    }
                    @Override public void onFinished(boolean cancelled, int completed, int total) {
                        done.countDown();
                    }
                });
        assertTrue(done.await(2, TimeUnit.SECONDS));
        assertTrue(captured.get(0).isError());
        runner.shutdown();
    }

    @Test
    void run_senderReturnsNullCell_cellMarkedAsError() throws Exception {
        RbacHttpSender sender = (ep, a, b) -> new RbacHttpSender.SendResult(null, null);
        RbacRunner runner = new RbacRunner(sender, 1);
        var captured = new ArrayList<RbacCellResult>();
        CountDownLatch done = new CountDownLatch(1);
        runner.run(
                List.of(endpoint(1, "/a")),
                List.of(identity("x")),
                new RbacRunner.Listener() {
                    @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {
                        captured.add(result);
                    }
                    @Override public void onFinished(boolean cancelled, int completed, int total) {
                        done.countDown();
                    }
                });
        assertTrue(done.await(2, TimeUnit.SECONDS));
        assertTrue(captured.get(0).isError());
        runner.shutdown();
    }

    @Test
    void cancel_stopsProcessingNewTasks() throws Exception {
        CountDownLatch firstTaskStarted = new CountDownLatch(1);
        CountDownLatch releaseFirstTask = new CountDownLatch(1);
        AtomicInteger sendCount = new AtomicInteger(0);
        RbacHttpSender sender = (ep, a, b) -> {
            firstTaskStarted.countDown();
            try { releaseFirstTask.await(); } catch (InterruptedException ignored) {}
            sendCount.incrementAndGet();
            return new RbacHttpSender.SendResult(RbacCellResult.ok(200, 0, 0), null);
        };
        RbacRunner runner = new RbacRunner(sender, 1); // single-threaded
        List<ApiEndpoint> endpoints = new ArrayList<>();
        for (int i = 1; i <= 10; i++) endpoints.add(endpoint(i, "/" + i));

        var listener = new RecordingListener();
        runner.run(endpoints, List.of(identity("x")), listener);
        firstTaskStarted.await(1, TimeUnit.SECONDS);
        runner.cancel();
        assertTrue(runner.isCancelled());
        releaseFirstTask.countDown();
        assertTrue(listener.finishLatch.await(3, TimeUnit.SECONDS));
        // Runner signals cancelled=true on finish.
        assertTrue(listener.wasCancelled, "should report cancelled");
        // Later tasks skipped their HTTP send — ensure count is low.
        assertTrue(sendCount.get() < endpoints.size(),
                "cancel should skip later sends; sent=" + sendCount.get());
        runner.shutdown();
    }

    @Test
    void run_twice_onSameRunner_throws() {
        RbacRunner runner = new RbacRunner((ep, a, b) ->
                new RbacHttpSender.SendResult(RbacCellResult.ok(200, 0, 0), null), 1);
        runner.run(List.of(endpoint(1, "/a")), List.of(identity("x")),
                new RbacRunner.Listener() {
                    @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {}
                    @Override public void onFinished(boolean cancelled, int completed, int total) {}
                });
        assertThrows(IllegalStateException.class,
                () -> runner.run(List.of(endpoint(1, "/a")), List.of(identity("x")),
                        new RbacRunner.Listener() {
                            @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {}
                            @Override public void onFinished(boolean cancelled, int completed, int total) {}
                        }));
        runner.shutdown();
    }

    @Test
    void constructor_rejectsZeroConcurrency() {
        assertThrows(IllegalArgumentException.class,
                () -> new RbacRunner((ep, a, b) -> null, 0));
    }

    @Test
    void constructor_rejectsNullSender() {
        assertThrows(NullPointerException.class, () -> new RbacRunner(null, 1));
    }

    @Test
    void run_rejectsNullArgs() {
        RbacRunner runner = new RbacRunner((ep, a, b) -> null, 1);
        RbacRunner.Listener noop = new RbacRunner.Listener() {
            @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {}
            @Override public void onFinished(boolean cancelled, int completed, int total) {}
        };
        assertThrows(NullPointerException.class, () -> runner.run(null, List.of(), noop));
        assertThrows(NullPointerException.class,
                () -> runner.run(List.of(), null, noop));
        assertThrows(NullPointerException.class,
                () -> runner.run(List.of(), List.of(), null));
        runner.shutdown();
    }

    @Test
    void raw_propagatedFromSenderToListener() throws Exception {
        Object expectedRaw = new Object();
        RbacHttpSender sender = (ep, a, b) ->
                new RbacHttpSender.SendResult(RbacCellResult.ok(200, 0, 0), expectedRaw);
        RbacRunner runner = new RbacRunner(sender, 1);
        CountDownLatch done = new CountDownLatch(1);
        Object[] receivedRaw = new Object[1];
        runner.run(List.of(endpoint(1, "/a")), List.of(identity("x")),
                new RbacRunner.Listener() {
                    @Override public void onCellComplete(int r, int c, RbacCellResult result, Object raw) {
                        receivedRaw[0] = raw;
                    }
                    @Override public void onFinished(boolean cancelled, int completed, int total) {
                        done.countDown();
                    }
                });
        assertTrue(done.await(2, TimeUnit.SECONDS));
        assertSame(expectedRaw, receivedRaw[0]);
        runner.shutdown();
    }

    @Test
    void abort_returnsWithoutWaitingForInFlightSends() throws Exception {
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch started = new CountDownLatch(1);
        RbacHttpSender sender = (ep, auth, base) -> {
            started.countDown();
            try { release.await(10, TimeUnit.SECONDS); } catch (InterruptedException ignored) { }
            return new RbacHttpSender.SendResult(RbacCellResult.ok(200, 0, 0), null);
        };
        RbacRunner runner = new RbacRunner(sender, 1);
        runner.run(List.of(endpoint(1, "/slow")), List.of(identity("a")), new RecordingListener());
        assertTrue(started.await(5, TimeUnit.SECONDS));

        long t0 = System.nanoTime();
        runner.abort();
        long elapsedMs = (System.nanoTime() - t0) / 1_000_000;

        assertTrue(elapsedMs < 1000, "abort blocked for " + elapsedMs + "ms");
        assertTrue(runner.isCancelled());
        release.countDown();
    }
}
