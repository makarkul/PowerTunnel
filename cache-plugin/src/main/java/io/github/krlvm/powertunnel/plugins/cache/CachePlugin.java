package io.github.krlvm.powertunnel.plugins.cache;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;

import io.github.krlvm.powertunnel.sdk.http.ProxyRequest;
import io.github.krlvm.powertunnel.sdk.http.ProxyResponse;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyAdapter;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import io.github.krlvm.powertunnel.sdk.types.FullAddress;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CachePlugin extends PowerTunnelPlugin {
    private static final Logger LOGGER = LoggerFactory.getLogger(CachePlugin.class);
    private static final long DEFAULT_TTL = 3600000; // 1 hour in milliseconds
    private static final String[] CACHEABLE_EXTENSIONS = {
        // Static web assets
        "html", "htm", "css", "js", "jpg", "jpeg", "png", "gif", "ico", "svg", "woff", "woff2", "ttf", "eot",
        // Video formats
        "mp4", "m4v", "m4s", "ts", "m3u8", "mpd", "mkv", "webm", "avi", "mov", "wmv", "flv", "f4v",
        // Audio formats
        "mp3", "aac", "m4a", "ogg", "wav"
    };



    private ConcurrentHashMap<String, CacheEntry> memoryCache;
    private ConcurrentHashMap<String, ProxyRequest> activeRequests;
    private Path cacheDir;
    
    private String generateCacheKey(String url) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(url.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("Failed to generate cache key", e);
            return Base64.getUrlEncoder().encodeToString(url.getBytes(StandardCharsets.UTF_8));
        }
    }

    private void saveToDisk(String cacheKey, CacheEntry entry) {
        if (cacheDir == null) {
            LOGGER.warn("=== CachePlugin: [CACHE ERROR] Directory not initialized, cannot save to disk for key {} ===", cacheKey);
            return;
        }

        LOGGER.warn("=== CachePlugin: [CACHE SAVE] Saving to disk - Size: {} bytes, Type: {} ===", 
            entry.content.length, entry.contentType);

        Path filePath = getCacheFilePath(cacheKey);
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath.toFile()))) {
            oos.writeObject(entry);
            LOGGER.warn("=== CachePlugin: [CACHE SAVE] Successfully saved to disk at {} ===", filePath);
        } catch (IOException e) {
            LOGGER.error("=== CachePlugin: [CACHE ERROR] Failed to save to disk with key: {} ===", cacheKey, e);
        }
    }



    private CacheEntry getCachedResponse(String cacheKey) {
        LOGGER.warn("=== CachePlugin: [CACHE CHECK] Looking for cache key: {} ===", cacheKey);
        
        // First try memory cache
        CacheEntry entry = memoryCache.get(cacheKey);
        if (entry != null) {
            LOGGER.warn("=== CachePlugin: [CACHE HIT] Found in memory cache! Size: {} bytes, Type: {} ===", 
                entry.content.length, entry.contentType);
        }
        
        // If not in memory, try disk cache
        if (entry == null) {
            LOGGER.warn("=== CachePlugin: [CACHE CHECK] Not found in memory cache, checking disk... ===");
            entry = loadFromDisk(cacheKey);
            if (entry != null) {
                LOGGER.warn("=== CachePlugin: [CACHE HIT] Found in disk cache! Size: {} bytes, Type: {} ===", 
                    entry.content.length, entry.contentType);
                // Put back in memory cache for faster access
                memoryCache.put(cacheKey, entry);
            } else {
                LOGGER.warn("=== CachePlugin: [CACHE MISS] Not found in disk cache ===");
            }
        }
        
        // Check if entry is expired
        if (entry != null && entry.isExpired()) {
            LOGGER.warn("=== CachePlugin: [CACHE EXPIRED] Cache entry expired for key {} ===", cacheKey);
            entry = null;
        }
        
        return entry;
    }

    private static class CacheEntry implements Serializable {
        private static final long serialVersionUID = 1L;
        
        private final byte[] content;
        private final String contentType;
        private final String contentEncoding;
        private final Instant timestamp;
        private final String etag;
        private final long ttl; // TTL in milliseconds
        
        public CacheEntry(byte[] content, String contentType, String contentEncoding, String etag, long ttl) {
            this.content = content;
            this.contentType = contentType;
            this.contentEncoding = contentEncoding;
            this.timestamp = Instant.now();
            this.etag = etag;
            this.ttl = ttl;
        }
        
        public boolean isExpired() {
            return Instant.now().isAfter(timestamp.plusMillis(ttl));
        }
    }

    public CachePlugin() {
        LOGGER.debug("=== CachePlugin: Constructor called ===");
        // Initialize memory cache
        memoryCache = new ConcurrentHashMap<>();
        activeRequests = new ConcurrentHashMap<>();
    }

    @Override
    public void onProxyInitialization(@NotNull ProxyServer proxy) {
        LOGGER.info("=== CachePlugin: [1/4] Initializing cache plugin ===");
        memoryCache = new ConcurrentHashMap<>();
        activeRequests = new ConcurrentHashMap<>();

        // Register our proxy listener
        this.registerProxyListener(new ProxyAdapter() {
            @Override
            public void onClientToProxyRequest(@NotNull ProxyRequest request) {
                // Log ALL requests, regardless of caching rules
                String url = request.getUri();
                LOGGER.warn("=== CachePlugin: RAW REQUEST: {} {} ===", 
                          request.getMethod(), 
                          url);
                LOGGER.warn("=== CachePlugin: Headers: {} ===",
                          request.headers());
                
                // Log potential video URLs
                if (url.contains("/Items/") || url.contains("/Video") || 
                    url.contains("/Stream") || url.contains("/PlaybackInfo") || 
                    url.contains("/Download") || url.contains("/Audio") || 
                    url.contains("/hls/") || url.contains(".m3u8") || 
                    url.contains(".ts") || url.contains(".mp4")) {
                    LOGGER.warn("=== CachePlugin: POTENTIAL VIDEO REQUEST FOUND: {} ===", url);
                }
            }
            
            @Override
            public void onProxyToClientResponse(@NotNull ProxyResponse response) {
                FullAddress address = response.address();
                if (address == null) {
                    LOGGER.warn("=== CachePlugin: No address in response ===");
                    return;
                }
                String url = address.toString();
                
                // Log ALL responses
                LOGGER.warn("=== CachePlugin: RAW RESPONSE for {}: {} {} ===",
                  url,
                  response.code(),
                  response.headers());
                
                // Only cache successful responses (200 OK) and partial content (206)
                if (response.code() != 200 && response.code() != 206) {
                    LOGGER.warn("=== CachePlugin: Not caching response with code {}: not 200 or 206 ===", response.code());
                    return;
                }

                // For 206 responses, only cache if we have the full content range
                if (response.code() == 206) {
                    String contentRange = response.headers().get("Content-Range");
                    if (contentRange == null) {
                        LOGGER.warn("=== CachePlugin: Not caching 206 response - missing Content-Range header ===");
                        return;
                    }
                    LOGGER.info("=== CachePlugin: DEBUG - Parsing Content-Range: {} ===", contentRange);
                    try {
                        String[] parts = contentRange.split(" ")[1].split("/");
                        LOGGER.info("=== CachePlugin: DEBUG - After first split: parts[1]={} ===", parts[1]);
                        String[] range = parts[0].split("-");
                        LOGGER.info("=== CachePlugin: DEBUG - Range parts: start={}, end={} ===", range[0], range[1]);
                        long start = Long.parseLong(range[0]);
                        long end = Long.parseLong(range[1]);
                        long total = Long.parseLong(parts[1]);
                        LOGGER.info("=== CachePlugin: DEBUG - Parsed values: start={}, end={}, total={} ===", start, end, total);
                        
                        // Only cache if this is the complete file
                        if (start != 0 || end + 1 != total) {
                            LOGGER.warn("=== CachePlugin: Not caching partial 206 response - range {}-{}/{} ===", start, end, total);
                            return;
                        }
                        LOGGER.info("=== CachePlugin: Caching complete 206 response - got full content {}-{}/{} ===", start, end, total);
                    } catch (Exception e) {
                        LOGGER.warn("=== CachePlugin: Not caching 206 response - invalid Content-Range header: {} ===", contentRange);
                        return;
                    }
                }

                // Get response details
                String contentType = response.headers().get("Content-Type");
                String contentEncoding = response.headers().get("Content-Encoding");
                String etag = response.headers().get("ETag");
                byte[] content = response.content();

                if (content == null || content.length == 0) {
                    LOGGER.warn("=== CachePlugin: Not caching empty response for: {} ===", url);
                    return;
                }

                // Create cache entry
                String cacheKey = generateCacheKey(url);
                CacheEntry entry = new CacheEntry(content, contentType, contentEncoding, etag, DEFAULT_TTL);

                // Save to memory and disk
                memoryCache.put(cacheKey, entry);
                saveToDisk(cacheKey, entry);

                LOGGER.warn("=== CachePlugin: Cached response for {}: {} bytes, type {} ===",
                  url,
                  content.length,
                  contentType);
            }
        });

        // Initialize cache directory
        try {
            String cacheBasePath = readConfiguration().get("cache_dir", System.getProperty("java.io.tmpdir") + "/powertunnel-cache");
            cacheDir = Files.createDirectories(Paths.get(cacheBasePath));
            LOGGER.warn("=== CachePlugin: Created cache directory at: {} ===", cacheDir);
        } catch (IOException e) {
            LOGGER.error("=== CachePlugin: Failed to create cache directory ===", e);
            // Set a default cache directory in case of failure
            cacheDir = Paths.get(System.getProperty("java.io.tmpdir"), "powertunnel-cache");
            try {
                Files.createDirectories(cacheDir);
                LOGGER.warn("=== CachePlugin: Created fallback cache directory at: {} ===", cacheDir);
            } catch (IOException ex) {
                LOGGER.error("=== CachePlugin: Failed to create fallback cache directory ===", ex);
            }
        }
        
        // Load existing cache entries from disk
        proxy.setFullRequest(true);

        this.registerProxyListener(new ProxyAdapter() {
            @Override
            public void onClientToProxyRequest(@NotNull ProxyRequest request) {
                // Log ALL requests that come through the proxy
                LOGGER.warn("=== CachePlugin: ALL REQUEST: {} {} with headers {} ===",
                          request.getMethod(), request.getUri(), request.headers());

                // Check if the request is cacheable
                if (!isCacheable(request)) {
                    return;
                }

                String cacheKey = generateCacheKey(request.getUri());
                activeRequests.put(cacheKey, request);

                LOGGER.info("=== CachePlugin: [3/4] Looking for cached response for {} ===", request.getUri());
                LOGGER.info("  Method: {}", request.getMethod());
                LOGGER.info("  URI: {}", request.getUri());
                LOGGER.info("  Host: {}", request.headers().get("Host"));
                LOGGER.info("  Cache-Control: {}", request.headers().get("Cache-Control"));
                LOGGER.info("  Pragma: {}", request.headers().get("Pragma"));
                LOGGER.info("  If-None-Match: {}", request.headers().get("If-None-Match"));
                LOGGER.info("  If-Modified-Since: {}", request.headers().get("If-Modified-Since"));

                String url = request.getUri();
                CacheEntry cachedResponse = getCachedResponse(cacheKey);

                if (cachedResponse != null) {
                    // Check if the client sent an If-None-Match header
                    String ifNoneMatch = request.headers().get("If-None-Match");
                    if (ifNoneMatch != null && ifNoneMatch.equals(cachedResponse.etag)) {
                        // Return 304 Not Modified
                        ProxyResponse notModifiedResponse = getServer().getProxyServer().getResponseBuilder("", 304).build();
                        request.setResponse(notModifiedResponse);
                        LOGGER.debug("=== CachePlugin: Returning 304 Not Modified for {} ===", url);
                        return;
                    }

                    // Return cached response
                    LOGGER.info("=== CachePlugin: [3/4] Cache hit! Serving cached response for {} ===", url);
                    ProxyResponse response = getServer().getProxyServer().getResponseBuilder("", 200)
                        .contentType(cachedResponse.contentType)
                        .build();
                    
                    response.setContent(cachedResponse.content);
                    
                    if (cachedResponse.contentEncoding != null) {
                        response.headers().set("Content-Encoding", cachedResponse.contentEncoding);
                    }
                    if (cachedResponse.etag != null) {
                        response.headers().set("ETag", cachedResponse.etag);
                    }
                    request.setResponse(response);
                    LOGGER.info("=== CachePlugin: [4/4] Cached response served successfully ===");
                } else {
                    LOGGER.info("=== CachePlugin: [3/4] Cache miss for {} - will fetch from origin ===", url);
                    activeRequests.put(cacheKey, request);
                    LOGGER.info("=== CachePlugin: [4/4] Request forwarded to origin server ===");
                }
            }

            @Override
            public void onProxyToClientResponse(@NotNull ProxyResponse response) {
                // For 304 Not Modified responses, update the cache entry's timestamp if we have it
                if (response.code() == 304) {
                    String url = response.headers().get("X-Original-URI");
                    if (url != null) {
                        String cacheKey = generateCacheKey(url);
                        CacheEntry entry = getCachedResponse(cacheKey);
                        if (entry != null) {
                            // Update the entry with new headers if present
                            String newEtag = response.headers().get("ETag");
                            if (newEtag != null) {
                                CacheEntry updatedEntry = new CacheEntry(
                                    entry.content,
                                    entry.contentType,
                                    entry.contentEncoding,
                                    newEtag,
                                    entry.ttl
                                );
                                memoryCache.put(cacheKey, updatedEntry);
                                saveToDisk(cacheKey, updatedEntry);
                                LOGGER.info("=== CachePlugin: Updated cache entry for {} with new ETag ===", url);
                            }
                        }
                    }
                }
                LOGGER.info("=== CachePlugin: [3/4] Response status: {} ===", response.code());
                LOGGER.info("=== CachePlugin: Response headers: {} ===", response.headers().toString());
                // Get the original URL from the request
                String url = response.headers().get("X-Original-URI");
                if (url == null) {
                    // Try to get it from the Host and path
                    String host = response.headers().get("Host");
                    String path = response.headers().get("Path");
                    if (host != null && path != null) {
                        url = "http://" + host + path;
                    } else {
                        LOGGER.debug("=== CachePlugin: No URL found in response headers ===");
                        return;
                    }
                }

                String cacheKey = CachePlugin.this.generateCacheKey(url);
                ProxyRequest request = activeRequests.remove(cacheKey);

                if (request != null) {
                    // Check if response is cacheable
                    String cacheControl = response.headers().get("Cache-Control");
                    if (cacheControl != null) {
                        String lowerCaseControl = cacheControl.toLowerCase();
                        if (lowerCaseControl.contains("no-store") || 
                            lowerCaseControl.contains("no-cache") || 
                            lowerCaseControl.contains("private")) {
                            LOGGER.debug("=== CachePlugin: Not caching due to Cache-Control: {} ===", cacheControl);
                            return;
                        }
                    }

                    // Get TTL from Cache-Control header
                    long ttl = DEFAULT_TTL;
                    if (cacheControl != null) {
                        String[] directives = cacheControl.split(",");
                        for (String directive : directives) {
                            directive = directive.trim().toLowerCase();
                            if (directive.startsWith("max-age=")) {
                                try {
                                    ttl = Long.parseLong(directive.substring(8)) * 1000L;
                                    if (ttl <= 0) {
                                        LOGGER.debug("=== CachePlugin: Not caching due to zero/negative max-age ===");
                                        return;
                                    }
                                    break;
                                } catch (NumberFormatException e) {
                                    LOGGER.warn("=== CachePlugin: Invalid max-age value in Cache-Control: {} ===", directive);
                                }
                            }
                        }
                    }

                    // Get response content and headers
                    byte[] content = response.content();
                    if (content == null) {
                        content = new byte[0];
                    }

                    String contentType = response.headers().get("Content-Type");
                    String contentEncoding = response.headers().get("Content-Encoding");
                    String etag = response.headers().get("ETag");
                    String contentRange = response.headers().get("Content-Range");
                    
                    if (contentRange != null) {
                        LOGGER.info("=== CachePlugin: Content-Range header present: {} ===", contentRange);
                    }

                    // Cache the response
                    // Use longer TTL for video content
                    if (contentType != null && (
                        contentType.startsWith("video/") || 
                        contentType.contains("mpegurl") || 
                        contentType.contains("mp2t") ||
                        contentType.contains("dash+xml"))) {
                        LOGGER.info("=== CachePlugin: Using extended TTL for video content ===");
                        ttl = DEFAULT_TTL * 24; // 24 hours for video content
                    }
                    
                    CacheEntry entry = new CacheEntry(response.content(), contentType, contentEncoding, etag, ttl);
                    memoryCache.put(cacheKey, entry);
                    saveToDisk(cacheKey, entry);
                    LOGGER.debug("=== CachePlugin: Cached response for {} (type={}, size={}, ttl={}ms) ===", 
                        url, contentType, content.length, ttl);
                }
            }
        });
    }

    
    private CacheEntry loadFromDisk(String cacheKey) {
        try {
            Path filePath = getCacheFilePath(cacheKey);
            if (Files.exists(filePath)) {
                try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(filePath.toFile()))) {
                    CacheEntry entry = (CacheEntry) ois.readObject();
                    LOGGER.debug("=== CachePlugin: Loaded from disk with key: {} ===", cacheKey);
                    return entry;
                }
            }
        } catch (IOException | ClassNotFoundException e) {
            LOGGER.error("=== CachePlugin: Failed to load from disk with key: {} ===", cacheKey, e);
        }
        return null;
    }
    
    private void deleteCacheFile(String cacheKey) {
        try {
            Path filePath = getCacheFilePath(cacheKey);
            Files.deleteIfExists(filePath);
            LOGGER.debug("=== CachePlugin: Deleted cache file with key: {} ===", cacheKey);
        } catch (IOException e) {
            LOGGER.error("=== CachePlugin: Failed to delete cache file with key: {} ===", cacheKey, e);
        }
    }
    
    private Path getCacheFilePath(String cacheKey) {
        return Paths.get(cacheDir.toString(), Base64.getUrlEncoder().encodeToString(cacheKey.getBytes(StandardCharsets.UTF_8)));
    }
    
    private void loadCacheFromDisk() {
        if (!Files.exists(cacheDir)) {
            return;
        }
        
        try {
            Files.list(cacheDir).forEach(file -> {
                String url = file.getFileName().toString().replaceAll("_", "/");
                CacheEntry entry = loadFromDisk(url);
                if (entry != null && !entry.isExpired()) {
                    memoryCache.put(url, entry);
                    LOGGER.debug("=== CachePlugin: Loaded cache entry for {} from disk ===", url);
                } else if (entry != null) {
                    deleteCacheFile(url);
                    LOGGER.debug("=== CachePlugin: Deleted expired cache entry for {} ===", url);
                }
            });
        } catch (IOException e) {
            LOGGER.error("=== CachePlugin: Failed to load cache from disk ===", e);
        }
    }

    private boolean isCacheable(ProxyRequest request) {
        String url = request.getUri().toLowerCase();
        String method = request.getMethod().toString();
        LOGGER.warn("=== CachePlugin: Received request: {} {} ===", method, url);
        LOGGER.warn("=== CachePlugin: Headers: {} ===", request.headers());

        // Handle CONNECT requests for HTTPS
        if ("CONNECT".equalsIgnoreCase(method)) {
            LOGGER.info("=== CachePlugin: Not cacheable - CONNECT request for {} ===", url);
            return false;
        }

        // Check if it's a GET request
        if (!"GET".equalsIgnoreCase(method)) {
            LOGGER.info("=== CachePlugin: Not cacheable - non-GET request: {} {} ===", method, url);
            return false;
        }

        // Check if this is a Jellyfin media request
        if (url.contains("/items/")) {
            // Check for theme media or direct video content
            if (url.contains("/thememedia") || url.contains("/download")) {
                LOGGER.warn("=== CachePlugin: Cacheable - Jellyfin video content: {} ===", url);
                LOGGER.warn("=== CachePlugin: Content-Type: {} ===", request.headers().get("Content-Type"));
                LOGGER.warn("=== CachePlugin: Range: {} ===", request.headers().get("Range"));
                return true;
            }
            
            // Check for video segments and manifests
            if ((url.contains("/videos/") || url.contains("/audio/") || 
                url.contains("/videostream") || url.contains("/playbackinfo") || url.contains("/stream") ||
                url.contains("/universal") || url.contains("/master.m3u8") ||
                url.contains("/manifest") || url.contains("/segments/") || url.contains(".ts") ||
                url.contains(".m4s") || url.contains(".mpd")) &&
                !url.contains("/sessions/") && !url.contains("/playing") && !url.contains("/users/")) {
                
                if (url.endsWith(".ts") || url.endsWith(".m4s") || url.endsWith(".mpd") || url.endsWith(".m3u8")) {
                    LOGGER.info("=== CachePlugin: Cacheable - Jellyfin media segment: {} ===", url);
                    LOGGER.info("=== CachePlugin: Content-Type: {} ===", request.headers().get("Content-Type"));
                    LOGGER.info("=== CachePlugin: Range: {} ===", request.headers().get("Range"));
                    return true;
                }
            }
            LOGGER.debug("=== CachePlugin: Not a cacheable media segment: {} ===", url);
        }

        // Check file extension
        int dotIndex = url.lastIndexOf(".");
        int slashIndex = url.lastIndexOf("/");
        int queryIndex = url.indexOf("?");
        
        if (dotIndex > slashIndex && dotIndex < url.length() - 1) {
            String extension;
            if (queryIndex > dotIndex) {
                extension = url.substring(dotIndex + 1, queryIndex);
            } else {
                extension = url.substring(dotIndex + 1);
            }
            
            LOGGER.debug("=== CachePlugin: Checking extension: {} ===", extension);
            if (Arrays.asList(CACHEABLE_EXTENSIONS).contains(extension.toLowerCase())) {
                LOGGER.info("=== CachePlugin: Cacheable - URL has valid extension: {} ===", extension);
                return true;
            }
        }

        // Handle URLs with query parameters
        if (queryIndex != -1) {
            // Allow query parameters for video-related URLs
            if (url.contains("/items/") || url.contains("/videos/") || url.contains("/audio/") || 
                url.contains("/videostream") || url.contains("/playbackinfo") || url.contains("/stream") ||
                url.contains("/download") || url.contains("/universal") || url.contains("/master.m3u8") ||
                url.contains("/manifest") || url.contains("/segments/")) {
                LOGGER.info("=== CachePlugin: Allowing query parameters for video URL: {} ===", url);
                return true;
            }
            LOGGER.info("=== CachePlugin: Not cacheable - URL has query parameters: {} ===", url);
            return false;
        }

        // Default to not caching if no explicit conditions are met
        LOGGER.info("=== CachePlugin: Not cacheable - No caching conditions met ===");
        return false;
    }
}
