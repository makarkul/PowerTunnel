package io.github.krlvm.powertunnel.plugins.cache;

import io.github.krlvm.powertunnel.sdk.http.ProxyRequest;
import io.github.krlvm.powertunnel.sdk.http.ProxyResponse;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyAdapter;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;
import io.github.krlvm.powertunnel.sdk.types.FullAddress;

import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.Base64;

public class CachePlugin extends PowerTunnelPlugin {
    // Per-connection request tracking
    private ProxyRequest currentRequest;
    private static final Logger LOGGER = LoggerFactory.getLogger("PowerTunnelCache");

    // Chunk buffering
    private final Map<String, ByteArrayOutputStream> chunkBuffers = new HashMap<>();
    private final Map<String, Map<String, String>> responseHeaders = new HashMap<>();

    private static final Set<String> CACHEABLE_EXTENSIONS = new HashSet<>(Arrays.asList(
        "jpg", "jpeg", "png", "gif", "webp", "ico", "bmp",  // Images
        "mp4", "webm", "m4v", "mkv", "avi", "mov",  // Videos
        "mp3", "m4a", "ogg", "wav", "flac",                           // Audio
        "js", "css", "woff", "woff2", "ttf", "eot",           // Web assets
        "bin", "dat", "iso"                                      // Binary files
    ));


    private Path cacheDir;

    private static class CacheEntry implements Serializable {
        private static final long serialVersionUID = 1L;

        private final byte[] content;
        private final String contentType;
        private final String contentEncoding;
        private final String etag;
        // Fields are accessed directly by the plugin code

        CacheEntry(byte[] content, String contentType, String contentEncoding, String etag) {
            this.content = content;
            this.contentType = contentType;
            this.contentEncoding = contentEncoding;
            this.etag = etag;
        }
    }

    private String generateCacheKey(String url) {
        try {
            // Normalize URL by removing trailing slashes and fragments
            url = url.replaceAll("/+$", "").replaceAll("#.*$", "");
            
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] urlBytes = url.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] hash = digest.digest(urlBytes);
            return java.util.Base64.getUrlEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            LOGGER.error("[CACHE] Failed to generate cache key: {} ===", e.getMessage());
            return java.util.Base64.getUrlEncoder().encodeToString(url.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
    }

    private String getFullUrl(ProxyRequest request) {
        String uri = request.getUri();
        String host = request.headers().get("Host");
        
        // Handle CONNECT requests
        if ("CONNECT".equalsIgnoreCase(request.getMethod().toString())) {
            // For CONNECT, the URI is typically host:port
            return uri;
        }
        
        // Handle absolute URLs
        if (uri.startsWith("http://") || uri.startsWith("https://")) {
            return uri;
        }
        
        // Handle case where host is null or empty
        if (host == null || host.isEmpty()) {
            // Try to extract host from URI if it's in the form host:port
            if (uri.contains(":")) {
                host = uri.split(":")[0];
            } else {
                LOGGER.error("[CACHE] No host found in request headers or URI ===");
                return uri;
            }
        }
        
        // Construct full URL from host and relative URI
        // Default to http:// since we can't reliably detect HTTPS
        return "http://" + host + (uri.startsWith("/") ? uri : "/" + uri);
    }

    private void saveToDisk(String cacheKey, CacheEntry entry) {
        if (cacheDir == null) {
            LOGGER.warn("[CACHE] [CACHE ERROR] Directory not initialized, cannot save to disk for key {} ===", cacheKey);
            return;
        }

        LOGGER.warn("[CACHE] [CACHE SAVE] Starting save to disk - Size: {} bytes, Type: {} ===", 
            entry.content.length, entry.contentType);

        Path filePath = getCacheFilePath(cacheKey);
        Path tempPath = null;
        try {
            // Create parent directories if they don't exist
            Files.createDirectories(filePath.getParent());
            
            // Write to a temporary file first
            tempPath = filePath.resolveSibling(filePath.getFileName() + ".tmp");
            LOGGER.warn("[CACHE] [CACHE SAVE] Writing to temp file: {} ===", tempPath);
            
            try (FileOutputStream fos = new FileOutputStream(tempPath.toFile());
                 ObjectOutputStream oos = new ObjectOutputStream(fos)) {
                oos.writeObject(entry);
                oos.flush();
                fos.getFD().sync(); // Force write to disk
                
                // Atomic rename to final path
                LOGGER.warn("[CACHE] [CACHE SAVE] Moving temp file to final path ===");
                Files.move(tempPath, filePath, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                                                java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                LOGGER.warn("[CACHE] [CACHE SAVE] Successfully saved to disk at {} ===", filePath);
            }
        } catch (Exception e) {
            LOGGER.error("[CACHE] [CACHE ERROR] Error saving cache entry: {} ===", e.getMessage());
            LOGGER.error("[CACHE] [CACHE ERROR] Full stack trace: ===", e);
            if (tempPath != null) {
                try {
                    Files.deleteIfExists(tempPath);
                    LOGGER.warn("[CACHE] [CACHE CLEANUP] Deleted temp file after error ===");
                } catch (IOException ex) {
                    LOGGER.error("[CACHE] [CACHE ERROR] Error deleting temp file: {} ===", ex.getMessage());
                    LOGGER.error("[CACHE] [CACHE ERROR] Full stack trace: ===", ex);
                }
            }
        }
    }

    private CacheEntry loadFromDisk(String cacheKey) {
        Path filePath = getCacheFilePath(cacheKey);
        if (!Files.exists(filePath)) {
            LOGGER.debug("[CACHE] Cache file not found: {} ===", filePath);
            return null;
        }

        try (FileInputStream fis = new FileInputStream(filePath.toFile());
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            LOGGER.warn("[CACHE] [CACHE LOAD] Loading cache entry from {} ===", filePath);
            CacheEntry entry = (CacheEntry) ois.readObject();
            LOGGER.warn("[CACHE] [CACHE LOAD] Successfully loaded cache entry ===");
            return entry;
        } catch (Exception e) {
            LOGGER.error("[CACHE] [CACHE ERROR] Error loading cache entry: {} ===", e.getMessage());
            LOGGER.error("[CACHE] [CACHE ERROR] Full stack trace: ===", e);
            try {
                Files.delete(filePath);
                LOGGER.warn("[CACHE] [CACHE CLEANUP] Deleted corrupted cache file: {} ===", filePath);
            } catch (IOException ex) {
                LOGGER.error("[CACHE] [CACHE ERROR] Error deleting corrupted cache file: {} ===", ex.getMessage());
                LOGGER.error("[CACHE] [CACHE ERROR] Full stack trace: ===", ex);
            }
            return null;
        }
    }

    private Path getCacheFilePath(String cacheKey) {
        // Create a two-level directory structure based on the first 4 chars of the key
        // This helps distribute files across directories to avoid too many files in one dir
        String encodedKey = Base64.getUrlEncoder().encodeToString(cacheKey.getBytes(StandardCharsets.UTF_8));
        String level1 = encodedKey.substring(0, 2);
        String level2 = encodedKey.substring(2, 4);
        return Paths.get(cacheDir.toString(), level1, level2, encodedKey);
    }

    private void cleanup(String fullUrl) {
        if (fullUrl != null) {
            chunkBuffers.remove(fullUrl);
            responseHeaders.remove(fullUrl);
        }
    }

    @Override
    public void onProxyInitialization(@NotNull ProxyServer server) {
        // Initialize cache directory
        try {
            String cacheDirPath = System.getProperty("user.home") + File.separator + ".powertunnel" + File.separator + "cache";
            cacheDir = Paths.get(cacheDirPath);
            Files.createDirectories(cacheDir);
            LOGGER.warn("[CACHE] Cache directory: {} ===", cacheDir);
        } catch (Exception e) {
            LOGGER.error("[CACHE] Failed to create cache directory: {} ===", e.getMessage(), e);
        }

        // Register proxy listener
        registerProxyListener(new ProxyAdapter() {
        @Override
        public Integer onGetChunkSize(@NotNull FullAddress address) {
            Integer chunkSize = super.onGetChunkSize(address);
            LOGGER.warn("=== [CHUNK] ProxyAdapter.onGetChunkSize called for {} with chunk size {} ===", address, chunkSize);
            return chunkSize;
        }

            @Override
            public void onClientToProxyRequest(@NotNull ProxyRequest request) {
                LOGGER.warn("[CACHE] [1/4] onClientToProxyRequest - Thread: {} ===", Thread.currentThread().getName());
                // Store request for correlation with response
                currentRequest = request;
                
                // Get full URL including host
                String fullUrl = getFullUrl(request);
                
                // Log request details
                LOGGER.warn("[CACHE] RAW REQUEST: {} {} ===", 
                          request.getMethod(),
                          fullUrl);
                LOGGER.warn("[CACHE] Headers: {} ===",
                          request.headers());
                
                // Check if request is cacheable
                if (!isCacheable(request)) {
                    LOGGER.warn("[CACHE] Request not cacheable: {} ===", fullUrl);
                    return;
                }
                
                // Try to load from cache using full URL
                String cacheKey = generateCacheKey(fullUrl);
                CacheEntry entry = loadFromDisk(cacheKey);
                
                if (entry == null) {
                    LOGGER.warn("[CACHE] Cache miss: {} ===", fullUrl);
                    return;
                }
                
                // Check If-None-Match header
                String ifNoneMatch = request.headers().get("If-None-Match");
                String etag = entry.etag;
                
                if (ifNoneMatch != null && etag != null && ifNoneMatch.equals(etag)) {
                    LOGGER.warn("[CACHE] 304 Not Modified: {} ===", fullUrl);
                    ProxyResponse response = server.getResponseBuilder(null)
                        .code(304)
                        .header("ETag", etag)
                        .header("X-Cache", "HIT")
                        .build();
                    request.setResponse(response);
                    return;
                }
                
                // Serve from cache
                byte[] content = entry.content;
                ProxyResponse.Builder responseBuilder = server.getResponseBuilder(new String(content, StandardCharsets.UTF_8))
                    .code(200)
                    .contentType(entry.contentType)
                    .header("Content-Length", String.valueOf(content.length))
                    .header("X-Cache", "HIT");
                
                if (entry.contentEncoding != null) {
                    responseBuilder.header("Content-Encoding", entry.contentEncoding);
                }
                
                if (entry.etag != null) {
                    responseBuilder.header("ETag", entry.etag);
                }
                
                ProxyResponse response = responseBuilder.build();
                request.setResponse(response);
                LOGGER.warn("[CACHE] Served from cache: {} ({} bytes) ===", fullUrl, content.length);
                
                // Important: Return immediately after serving from cache to avoid further processing
                return;
            }
            
            @Override
            public void onProxyToServerRequest(@NotNull ProxyRequest request) {
                try {
                    LOGGER.warn("[CACHE] [2/4] onProxyToServerRequest - Thread: {} ===", Thread.currentThread().getName());
                    String originalUrl = getFullUrl(currentRequest);  // Use stored request
                    LOGGER.warn("[CACHE] [2/4] URL from stored request: {} ===", originalUrl);
                    if (originalUrl != null && !originalUrl.isEmpty()) {
                        LOGGER.warn("[CACHE] Propagating URL to server request: {} ===", originalUrl);
                    }
                } catch (Exception e) {
                    LOGGER.error("[CACHE] Error in onProxyToServerRequest: {} ===", e.getMessage(), e);
                }
            }

            @Override
            public void onServerToProxyResponse(@NotNull ProxyResponse response) {
                try {
                    LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse ENTRY - Thread: {} ===", Thread.currentThread().getName());
                    String fullUrl = getFullUrl(currentRequest);
                    LOGGER.warn("[CACHE] [3/4] URL from stored request: {} ===", fullUrl);
                    LOGGER.warn("[CACHE] [3/4] Response code: {} ===", response.code());
                    LOGGER.warn("[CACHE] [3/4] All response headers: {} ===", response.headers());

                    // Store headers for this response
                    Map<String, String> headers = new HashMap<>();
                    for (String name : response.headers().names()) {
                        headers.put(name, response.headers().get(name));
                    }
                    responseHeaders.put(fullUrl, headers);

                    // Initialize chunk buffer if needed
                    if (!chunkBuffers.containsKey(fullUrl)) {
                        chunkBuffers.put(fullUrl, new ByteArrayOutputStream());
                    }

                    // If we have content, add it to the buffer
                    if (response.isDataPacket()) {
                        byte[] content = response.content();
                        if (content != null && content.length > 0) {
                            LOGGER.warn("[CACHE] [3/4] Adding {} bytes to chunk buffer for {} ===", content.length, fullUrl);
                            chunkBuffers.get(fullUrl).write(content);
                        }
                    }

                    LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                } catch (Exception e) {
                    LOGGER.error("[CACHE] Error in onServerToProxyResponse: {} ===", e.getMessage(), e);
                }
            }

            @Override
            public void onProxyToClientResponse(@NotNull ProxyResponse response) {
                try {
                    String fullUrl = getFullUrl(currentRequest);
                    if (!isCacheable(currentRequest)) {
                        LOGGER.warn("[CACHE] Request not cacheable: {} ===", fullUrl);
                        cleanup(fullUrl);
                        return;
                    }

                    // Get the buffered content
                    ByteArrayOutputStream buffer = chunkBuffers.get(fullUrl);
                    Map<String, String> headers = responseHeaders.get(fullUrl);
                    
                    if (buffer == null || headers == null) {
                        LOGGER.warn("[CACHE] No buffered content or headers for {} ===", fullUrl);
                        cleanup(fullUrl);
                        return;
                    }

                    // Add any final content
                    if (response.isDataPacket()) {
                        byte[] content = response.content();
                        if (content != null && content.length > 0) {
                            LOGGER.warn("[CACHE] Adding final {} bytes to chunk buffer for {} ===", content.length, fullUrl);
                            buffer.write(content);
                        }
                    }

                    byte[] finalContent = buffer.toByteArray();
                    if (finalContent.length == 0) {
                        LOGGER.error("[CACHE] Empty response body after buffering ===");
                        cleanup(fullUrl);
                        return;
                    }

                    // Get required headers from stored headers
                    String contentType = headers.get("Content-Type");
                    String contentEncoding = headers.get("Content-Encoding");
                    String etag = headers.get("ETag");

                    if (contentType == null) {
                        LOGGER.warn("[CACHE] Missing required headers ===");
                        cleanup(fullUrl);
                        return;
                    }

                    // Create cache entry
                    CacheEntry entry = new CacheEntry(finalContent, contentType, contentEncoding, etag);

                    // Save to disk using full URL as key
                    String cacheKey = generateCacheKey(fullUrl);
                    saveToDisk(cacheKey, entry);

                    LOGGER.warn("[CACHE] Response cached: {} ({} bytes, type: {}) ===",
                        fullUrl, finalContent.length, contentType);

                    // Clean up
                    cleanup(fullUrl);
                } catch (Exception e) {
                    LOGGER.error("[CACHE] Error in onProxyToClientResponse: {} ===", e.getMessage(), e);
                    cleanup(getFullUrl(currentRequest));
                }
            }

            private boolean isCacheable(ProxyRequest request) {
                String method = request.getMethod().toString();
                String url = getFullUrl(request);
                
                // Allow caching for CONNECT requests to known static content hosts
                if ("CONNECT".equalsIgnoreCase(method)) {
                    String host = request.headers().get("Host");
                    if (host != null && (host.equals("example.com:443") || host.startsWith("10.0.2.2:"))) {
                        LOGGER.warn("[CACHE] Allowing cache for trusted HTTPS host: {}", url);
                        return true;
                    }
                    LOGGER.warn("[CACHE] Not cacheable - CONNECT request for {}", url);
                    return false;
                }

                // Only cache GET requests
                if (!"GET".equalsIgnoreCase(method)) {
                    LOGGER.info("[CACHE] Not cacheable - non-GET request: {} ===", method);
                    return false;
                }

                // Check if this is a Jellyfin media request
                if (url.contains("/items/")) {
                    // Check for theme media or direct video content
                    if (url.contains("/thememedia") || url.contains("/download")) {
                        LOGGER.warn("[CACHE] Cacheable - Jellyfin video content: {} ===", url);
                        LOGGER.warn("[CACHE] Content-Type: {} ===", request.headers().get("Content-Type"));
                        LOGGER.warn("[CACHE] Range: {} ===", request.headers().get("Range"));
                        return true;
                    }
                    
                    // Check for video segments and manifests
                    if (url.contains("/videos/") || url.contains("/audio/") || 
                        url.contains("/videostream") || url.contains("/playbackinfo") || 
                        url.contains("/stream") || url.contains("/universal") || 
                        url.contains("/master.m3u8") || url.contains("/manifest") || 
                        url.contains("/segments/") || url.contains(".ts") || 
                        url.contains(".m4s") || url.contains(".mpd")) {
                        LOGGER.info("[CACHE] Cacheable - Jellyfin media segment: {} ===", url);
                        return true;
                    }
                }

                // Check file extension
                try {
                    int dotIndex = url.lastIndexOf('.');
                    if (dotIndex == -1) return false;
                    String extension = url.substring(dotIndex + 1).toLowerCase();
                    return CACHEABLE_EXTENSIONS.contains(extension);
                } catch (Exception e) {
                    LOGGER.error("[CACHE] Error checking cacheability: {} ===", e.getMessage());
                    return false;
                }
            }
        });
    }
}
