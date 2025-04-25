package io.github.krlvm.powertunnel.plugins.cache;

import io.github.krlvm.powertunnel.sdk.http.ProxyRequest;
import io.github.krlvm.powertunnel.sdk.http.ProxyResponse;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyAdapter;
import io.github.krlvm.powertunnel.sdk.proxy.ProxyServer;
import io.github.krlvm.powertunnel.sdk.plugin.PowerTunnelPlugin;

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

    private static class CacheEntry implements Serializable {
        private static final long serialVersionUID = 1L;

        private final byte[] content;
        private final String contentType;
        private final String contentEncoding;
        private final String etag;

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
        try {
            // Initialize cache directory
            cacheDir = Paths.get("/data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel");
            Files.createDirectories(cacheDir);
            LOGGER.info("[CACHE] Initialized cache directory: {} ===", cacheDir);

            this.registerProxyListener(new ProxyAdapter() {
                @Override
                public void onClientToProxyRequest(@NotNull ProxyRequest request) {
                    try {
                        currentRequest = request;
                        String fullUrl = getFullUrl(request);
                        LOGGER.warn("[CACHE] [1/4] onClientToProxyRequest for {} ===", fullUrl);

                        if (!isCacheable(request)) {
                            LOGGER.info("[CACHE] Not cacheable: {} ===", fullUrl);
                            return;
                        }

                        // Try to load from cache
                        String cacheKey = generateCacheKey(fullUrl);
                        CacheEntry entry = loadFromDisk(cacheKey);
                        if (entry == null) {
                            LOGGER.info("[CACHE] Cache miss: {} ===", fullUrl);
                            return;
                        }

                        // Build response from cache
                        ProxyResponse response = server.getResponseBuilder(new String(entry.content, StandardCharsets.UTF_8))
                            .code(200)
                            .header("Content-Length", String.valueOf(entry.content.length))
                            .header("X-Cache", "HIT")
                            .build();

                        // Add optional headers
                        if (entry.contentType != null) {
                            response.headers().set("Content-Type", entry.contentType);
                        }
                        if (entry.contentEncoding != null) {
                            response.headers().set("Content-Encoding", entry.contentEncoding);
                        }
                        if (entry.etag != null) {
                            response.headers().set("ETag", entry.etag);
                        }

                        request.setResponse(response);
                        LOGGER.warn("[CACHE] Served from cache: {} ({} bytes) ===", fullUrl, entry.content.length);
                    } catch (Exception e) {
                        LOGGER.error("[CACHE] Error in onClientToProxyRequest: {} ===", e.getMessage(), e);
                    }
                }

                @Override
                public void onServerToProxyResponse(@NotNull ProxyResponse response) {
                    try {
                        String fullUrl = getFullUrl(currentRequest);
                        LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse for {} ===", fullUrl);

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

                        // Get content if available
                        try {
                            if (response.isDataPacket()) {
                                byte[] content = response.content();
                                LOGGER.warn("[CACHE] [3/4] Content is null: {}, Content class: {} ===", (content == null), (content != null ? content.getClass().getName() : "null"));
                                if (content != null && content.length > 0) {
                                    LOGGER.warn("[CACHE] [3/4] Writing {} bytes to buffer ===", content.length);
                                    chunkBuffers.get(fullUrl).write(content);
                                } else {
                                    LOGGER.warn("[CACHE] [3/4] Data packet has no content ===");
                                    // Try to extract content using reflection by examining all fields
                                    try {
                                        Class<?> responseClass = response.getClass();
                                        java.lang.reflect.Field[] fields = responseClass.getDeclaredFields();
                                        LOGGER.warn("[CACHE] [3/4] Examining {} fields in {} ===", fields.length, responseClass.getName());
                                        
                                        // Try all fields that might contain the HTTP content
                                        for (java.lang.reflect.Field field : fields) {
                                            field.setAccessible(true);
                                            String fieldName = field.getName();
                                            LOGGER.warn("[CACHE] [3/4] Checking field: {} of type {} ===", fieldName, field.getType().getName());
                                            
                                            try {
                                                Object fieldValue = field.get(response);
                                                if (fieldValue != null) {
                                                    // If field is an HttpContent or contains a ByteBuf
                                                    if (fieldValue instanceof io.netty.handler.codec.http.HttpContent) {
                                                        io.netty.handler.codec.http.HttpContent httpContent = (io.netty.handler.codec.http.HttpContent) fieldValue;
                                                        io.netty.buffer.ByteBuf buf = httpContent.content();
                                                        if (buf != null && buf.readableBytes() > 0) {
                                                            byte[] bytes = new byte[buf.readableBytes()];
                                                            buf.getBytes(buf.readerIndex(), bytes);
                                                            LOGGER.warn("[CACHE] [3/4] Got {} bytes from field {} ===", bytes.length, fieldName);
                                                            chunkBuffers.get(fullUrl).write(bytes);
                                                            break;
                                                        }
                                                    } else if (fieldValue instanceof io.netty.buffer.ByteBuf) {
                                                        io.netty.buffer.ByteBuf buf = (io.netty.buffer.ByteBuf) fieldValue;
                                                        if (buf.readableBytes() > 0) {
                                                            byte[] bytes = new byte[buf.readableBytes()];
                                                            buf.getBytes(buf.readerIndex(), bytes);
                                                            LOGGER.warn("[CACHE] [3/4] Got {} bytes from ByteBuf field {} ===", bytes.length, fieldName);
                                                            chunkBuffers.get(fullUrl).write(bytes);
                                                            break;
                                                        }
                                                    }
                                                }
                                            } catch (Exception e) {
                                                LOGGER.warn("[CACHE] [3/4] Error accessing field {}: {} ===", fieldName, e.getMessage());
                                            }
                                        }
                                    } catch (Exception e) {
                                        LOGGER.error("[CACHE] [3/4] Error getting content via reflection: {} ===", e.getMessage());
                                    }
                                }
                            } else {
                                // This might be a chunked response
                                String transferEncoding = response.headers().get("Transfer-Encoding");
                                if ("chunked".equalsIgnoreCase(transferEncoding)) {
                                    LOGGER.warn("[CACHE] [3/4] Chunked response detected ===");
                                    // We'll collect chunks in onProxyToClientResponse
                                } else {
                                    LOGGER.warn("[CACHE] [3/4] Not a data packet or chunked response ===");
                                }
                            }
                        } catch (IllegalStateException e) {
                            LOGGER.warn("[CACHE] [3/4] Cannot get content: {} ===", e.getMessage());
                        }

                        LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                    } catch (Exception e) {
                        LOGGER.error("[CACHE] Error in onServerToProxyResponse: {} ===", e.getMessage(), e);
                        cleanup(getFullUrl(currentRequest));
                    }
                }

                @Override
                public void onProxyToClientResponse(@NotNull ProxyResponse response) {
                    try {
                        String fullUrl = getFullUrl(currentRequest);
                        LOGGER.warn("[CACHE] [4/4] onProxyToClientResponse for {} ===", fullUrl);

                        ByteArrayOutputStream buffer = chunkBuffers.get(fullUrl);
                        Map<String, String> headers = responseHeaders.get(fullUrl);

                        if (buffer == null || headers == null) {
                            LOGGER.warn("[CACHE] No buffered content or headers for {} ===", fullUrl);
                            cleanup(fullUrl);
                            return;
                        }
                        
                        // If our buffer is empty, try to get content from the response
                        if (buffer.size() == 0 && response.isDataPacket()) {
                            try {
                                byte[] content = response.content();
                                if (content != null && content.length > 0) {
                                    LOGGER.warn("[CACHE] [4/4] Got {} bytes from response in final stage ===", content.length);
                                    buffer.write(content);
                                } else {
                                    // Try to extract content using reflection by examining all fields
                                    try {
                                        Class<?> responseClass = response.getClass();
                                        java.lang.reflect.Field[] fields = responseClass.getDeclaredFields();
                                        LOGGER.warn("[CACHE] [4/4] Examining {} fields in {} ===", fields.length, responseClass.getName());
                                        
                                        // Try all fields that might contain the HTTP content
                                        for (java.lang.reflect.Field field : fields) {
                                            field.setAccessible(true);
                                            String fieldName = field.getName();
                                            LOGGER.warn("[CACHE] [4/4] Checking field: {} of type {} ===", fieldName, field.getType().getName());
                                            
                                            try {
                                                Object fieldValue = field.get(response);
                                                if (fieldValue != null) {
                                                    // If field is an HttpContent or contains a ByteBuf
                                                    if (fieldValue instanceof io.netty.handler.codec.http.HttpContent) {
                                                        io.netty.handler.codec.http.HttpContent httpContent = (io.netty.handler.codec.http.HttpContent) fieldValue;
                                                        io.netty.buffer.ByteBuf buf = httpContent.content();
                                                        if (buf != null && buf.readableBytes() > 0) {
                                                            byte[] bytes = new byte[buf.readableBytes()];
                                                            buf.getBytes(buf.readerIndex(), bytes);
                                                            LOGGER.warn("[CACHE] [4/4] Got {} bytes from field {} ===", bytes.length, fieldName);
                                                            buffer.write(bytes);
                                                            break;
                                                        }
                                                    } else if (fieldValue instanceof io.netty.buffer.ByteBuf) {
                                                        io.netty.buffer.ByteBuf buf = (io.netty.buffer.ByteBuf) fieldValue;
                                                        if (buf.readableBytes() > 0) {
                                                            byte[] bytes = new byte[buf.readableBytes()];
                                                            buf.getBytes(buf.readerIndex(), bytes);
                                                            LOGGER.warn("[CACHE] [4/4] Got {} bytes from ByteBuf field {} ===", bytes.length, fieldName);
                                                            buffer.write(bytes);
                                                            break;
                                                        }
                                                    }
                                                }
                                            } catch (Exception e) {
                                                LOGGER.warn("[CACHE] [4/4] Error accessing field {}: {} ===", fieldName, e.getMessage());
                                            }
                                        }
                                    } catch (Exception e) {
                                        LOGGER.warn("[CACHE] [4/4] Could not access httpObject field: {} ===", e.getMessage());
                                    }
                                }
                            } catch (Exception e) {
                                LOGGER.error("[CACHE] [4/4] Error getting content in final stage: {} ===", e.getMessage());
                            }
                        }

                        byte[] finalContent = buffer.toByteArray();
                        LOGGER.warn("[CACHE] Final content size: {} bytes ===", finalContent.length);

                        if (finalContent.length == 0) {
                            LOGGER.error("[CACHE] Empty response body after buffering ===");
                            cleanup(fullUrl);
                            return;
                        }

                        String contentType = headers.get("Content-Type");
                        String contentEncoding = headers.get("Content-Encoding");
                        String etag = headers.get("ETag");

                        LOGGER.warn("[CACHE] Content-Type: {}, Content-Encoding: {}, ETag: {} ===", 
                        contentType, contentEncoding, etag);

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

                        LOGGER.warn("[CACHE] Response cached successfully: {} ({} bytes, type: {}) ===",
                        fullUrl, finalContent.length, contentType);

                        // Clean up
                        cleanup(fullUrl);
                    } catch (Exception e) {
                        LOGGER.error("[CACHE] Error in onProxyToClientResponse: {} ===", e.getMessage(), e);
                        cleanup(getFullUrl(currentRequest));
                    }
                }
            });
        } catch (Exception e) {
            LOGGER.error("[CACHE] Error in onProxyInitialization: {} ===", e.getMessage(), e);
        }
    }
}
