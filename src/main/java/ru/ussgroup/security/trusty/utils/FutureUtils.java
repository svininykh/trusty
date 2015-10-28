package ru.ussgroup.security.trusty.utils;

import java.util.concurrent.CompletableFuture;

import com.ning.http.client.ListenableFuture;

public class FutureUtils {
    public static <T> CompletableFuture<T> toCompletable(ListenableFuture<T> listenableFuture) {
        CompletableFuture<T> completableFuture = new CompletableFuture<T>();
        
        listenableFuture.addListener(() -> {
            try {
                completableFuture.complete(listenableFuture.get());
            } catch (Exception e) {
                completableFuture.completeExceptionally(e);
            }
        }, r -> {r.run();});
        
        return completableFuture;
    }
}
