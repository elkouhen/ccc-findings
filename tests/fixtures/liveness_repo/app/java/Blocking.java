package com.example.app;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public class Blocking {

    public void waitBad(Thread t) throws InterruptedException {
        t.join();
    }

    public void waitGood(Thread t) throws InterruptedException {
        t.join(10_000);
    }

    public void joinFutureBad(CompletableFuture<String> future) {
        future.join();
    }

    public String futureGetBad(Future<String> future) throws ExecutionException, InterruptedException {
        Future<String> f = future;
        return f.get();
    }

    public String futureGetGood(Future<String> future)
            throws ExecutionException, InterruptedException, TimeoutException {
        Future<String> f = future;
        return f.get(5, TimeUnit.SECONDS);
    }

    public String completableFutureGetBad(CompletableFuture<String> cf)
            throws ExecutionException, InterruptedException {
        CompletableFuture<String> f = cf;
        return f.get();
    }

    public String completableFutureGetGood(CompletableFuture<String> cf)
            throws ExecutionException, InterruptedException, TimeoutException {
        CompletableFuture<String> f = cf;
        return f.get(5, TimeUnit.SECONDS);
    }
}
