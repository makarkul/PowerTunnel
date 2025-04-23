package io.github.krlvm.powertunnel.plugins.cache;

import io.github.krlvm.powertunnel.sdk.http.ProxyResponse;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class CacheManager {
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();
    private static final long DEFAULT_TTL = 3600000; // 1 hour in milliseconds
    private static final Logger LOGGER = LoggerFactory.getLogger(CacheManager.class);

    public void put(@NotNull String key, @NotNull ProxyResponse response) {
        // Calculate TTL based on Cache-Control or Expires headers
        long ttl = calculateTTL(response);

        LOGGER.info("Caching response for {} with TTL={}", key, ttl);

        cache.put(key, new CacheEntry(response, ttl));
    }

    private long calculateTTL(ProxyResponse response) {
        // Try to get Cache-Control max-age
        String cacheControl = response.headers().get("Cache-Control");
        if (cacheControl != null) {
            for (String directive : cacheControl.split(",")) {
                directive = directive.trim();
                if (directive.startsWith("max-age=")) {
                    try {
                        return Long.parseLong(directive.substring(8)) * 1000; // Convert to milliseconds
                    } catch (NumberFormatException e) {
                        // Ignore parsing errors
                    }
                }
            }
        }

        // Try to get Expires header
        String expires = response.headers().get("Expires");
        if (expires != null) {
            try {
                SimpleDateFormat format = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz", Locale.US);
                Date expiresDate = format.parse(expires);
                if (expiresDate != null) {
                    long ttl = expiresDate.getTime() - System.currentTimeMillis();
                    return ttl > 0 ? ttl : 0;
                }
            } catch (ParseException e) {
                // Ignore parsing errors
            }
        }

        return DEFAULT_TTL;
    }

    @Nullable
    public CacheEntry get(@NotNull String key) {
        CacheEntry entry = cache.get(key);
        if (entry == null) {
            LOGGER.debug("Cache miss for {}", key);
            return null;
        }

        if (entry.isExpired()) {
            LOGGER.debug("Cache entry expired for {}", key);
            cache.remove(key);
            return null;
        }

        LOGGER.debug("Cache hit for {}", key);
        return entry;
    }

    public void clear() {
        cache.clear();
    }

    public static class CacheEntry {
        private final ProxyResponse response;
        private final long timestamp;
        private final long ttl;
        private final Map<String, String> metadata;

        public CacheEntry(@NotNull ProxyResponse response) {
            this(response, DEFAULT_TTL);
        }

        public CacheEntry(@NotNull ProxyResponse response, long ttl) {
            this.response = response;
            this.timestamp = System.currentTimeMillis();
            this.ttl = ttl;
            this.metadata = new HashMap<>();
            
            // Store important headers as metadata
            String[] importantHeaders = {"Content-Type", "Content-Length", "ETag", "Last-Modified"};
            for (String header : importantHeaders) {
                String value = response.headers().get(header);
                if (value != null) {
                    metadata.put(header, value);
                }
            }
        }

        @NotNull
        public ProxyResponse getResponse() {
            return response;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > ttl;
        }

        public long getAge() {
            return System.currentTimeMillis() - timestamp;
        }

        public Map<String, String> getMetadata() {
            return metadata;
        }
    }
}
