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
import java.util.HashMap;
import java.util.Map;
import java.net.URL;
import java.net.ServerSocket;
import java.net.Socket;

public class CachePlugin extends PowerTunnelPlugin {
    // Per-connection request tracking
    private ProxyRequest currentRequest;
    private static final Logger LOGGER = LoggerFactory.getLogger("PowerTunnelCache");

    // Chunk buffering
    private final Map<String, ByteArrayOutputStream> chunkBuffers = new HashMap<>();
    private final Map<String, Map<String, String>> responseHeaders = new HashMap<>();
    private final Map<String, ByteArrayOutputStream> chunkData = new HashMap<>();

    private static final Set<String> CACHEABLE_EXTENSIONS = new HashSet<>(Arrays.asList(
        // Only cache media files, not web assets
        "mp4", "webm", "m4v", "mkv", "avi", "mov",  // Videos
        "mp3", "m4a", "ogg", "wav", "flac",         // Audio
        "bin", "dat", "iso"                          // Binary files
    ));


    private Path cacheDir;
    private ServerSocket adminServer;
    private int adminPort = 8081;
    private boolean adminServerRunning = false;
    private Thread adminServerThread;

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
        
        // Exclude authentication, session, and user-specific API endpoints
        String lowerUrl = url.toLowerCase();
        if (lowerUrl.contains("/auth") || 
            lowerUrl.contains("/login") || 
            lowerUrl.contains("/sessions") || 
            lowerUrl.contains("/users/") || 
            lowerUrl.contains("/token") || 
            lowerUrl.contains("/api_key") || 
            lowerUrl.contains("/system/info") || 
            lowerUrl.contains("/config") ||
            lowerUrl.contains("/strings/") ||
            lowerUrl.contains("/translations/") ||
            lowerUrl.contains("/localization/") ||
            lowerUrl.contains("/branding/") ||
            lowerUrl.contains("/web/") ||
            lowerUrl.contains("/bundle.js") ||
            lowerUrl.contains("/main.js") ||
            lowerUrl.contains("/chunk") ||
            lowerUrl.contains("/resources")) {
            LOGGER.warn("[CACHE] Not cacheable - Auth/Session/UI/Dynamic request: {} ===", url);
            return false;
        }
        
        // Explicitly identify Jellyfin image requests (don't cache but allow to pass through)
        if (url.toLowerCase().contains("/items/") && 
            (url.toLowerCase().contains("/images/") || 
             url.toLowerCase().matches(".*?/image[^a-z].*"))) {
            LOGGER.warn("[CACHE] Not cacheable - Jellyfin image request: {} ===", url);
            return false;
        }

        // Check if this is a Jellyfin media request
        if (url.contains("/items/") || url.contains("/Videos/")) {
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
                url.contains(".m4s") || url.contains(".mpd") ||
                url.toLowerCase().contains("stream.mp4")) {
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
        // Normalize Jellyfin video stream URLs to ensure consistent cache keys
        if (url.contains("/Videos/") && url.contains("/stream.mp4")) {
            try {
                LOGGER.warn("[CACHE] Normalizing Jellyfin video URL for caching: {} ===", url);
                
                // Extract the video ID from the URL path
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("/Videos/([^/]+)/stream");
                java.util.regex.Matcher matcher = pattern.matcher(url);
                String videoId = "";
                if (matcher.find()) {
                    videoId = matcher.group(1);
                }
                
                // Extract any important static parameters that should be part of the cache key
                // (like startTimeTicks, playSessionId, etc.)
                URL originalUrl = new URL(url);
                String query = originalUrl.getQuery();
                Map<String, String> staticParams = new HashMap<>();
                
                if (query != null && !query.isEmpty()) {
                    String[] pairs = query.split("&");
                    for (String pair : pairs) {
                        String[] keyValue = pair.split("=");
                        if (keyValue.length == 2) {
                            String key = keyValue[0].toLowerCase();
                            // Keep only parameters that affect content but aren't session-specific
                            if (key.equals("static") || 
                                key.equals("mediasourceid") || 
                                key.equals("starttimeticks") || 
                                key.equals("audiobitrate") || 
                                key.equals("videobitrate") || 
                                key.equals("maxwidth") || 
                                key.equals("maxheight") || 
                                key.equals("container") || 
                                key.equals("subtitlemethod")) {
                                staticParams.put(key, keyValue[1]);
                            }
                        }
                    }
                }
                
                // Create a normalized URL with just the essential parts
                StringBuilder normalizedUrl = new StringBuilder();
                normalizedUrl.append(originalUrl.getProtocol()).append("://").append(originalUrl.getHost());
                if (originalUrl.getPort() != -1) {
                    normalizedUrl.append(":").append(originalUrl.getPort());
                }
                normalizedUrl.append(originalUrl.getPath()).append("?videoId=").append(videoId);
                
                // Add any static parameters that affect content
                for (Map.Entry<String, String> entry : staticParams.entrySet()) {
                    normalizedUrl.append("&").append(entry.getKey()).append("=").append(entry.getValue());
                }
                
                LOGGER.warn("[CACHE] Normalized URL: {} ===", normalizedUrl.toString());
                return normalizedUrl.toString();
            } catch (Exception e) {
                LOGGER.error("[CACHE] Error normalizing Jellyfin URL: {}", e.getMessage());
            }
        }    
        
        // Normalize URL by removing trailing slashes and fragments
        url = url.replaceAll("/+$", "").replaceAll("#.*$", "");
        
        try {
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
        chunkBuffers.remove(fullUrl);
        responseHeaders.remove(fullUrl);
        chunkData.remove(fullUrl);
    }

    private void startAdminServer() {
        if (adminServerRunning) {
            LOGGER.info("[CACHE] Admin server already running on port {}", adminPort);
            return;
        }
        
        adminServerThread = new Thread(() -> {
            try {
                adminServer = new ServerSocket(adminPort);
                adminServerRunning = true;
                LOGGER.info("[CACHE] Admin server started on port {}", adminPort);
                
                while (adminServerRunning) {
                    try {
                        Socket clientSocket = adminServer.accept();
                        new Thread(() -> handleClientConnection(clientSocket)).start();
                    } catch (IOException e) {
                        if (adminServerRunning) {
                            LOGGER.error("[CACHE] Error accepting client connection: {}", e.getMessage());
                        }
                    }
                }
            } catch (IOException e) {
                LOGGER.error("[CACHE] Error starting admin server: {}", e.getMessage());
            } finally {
                stopAdminServer();
            }
        });
        
        adminServerThread.setDaemon(true);
        adminServerThread.start();
    }

    private void stopAdminServer() {
        adminServerRunning = false;
        if (adminServer != null) {
            try {
                adminServer.close();
                LOGGER.info("[CACHE] Admin server stopped");
            } catch (IOException e) {
                LOGGER.error("[CACHE] Error stopping admin server: {}", e.getMessage());
            }
        }
    }

    private void handleClientConnection(Socket clientSocket) {
        try {
            // Set a reasonable timeout to prevent hanging connections
            clientSocket.setSoTimeout(30000); // 30 seconds
            LOGGER.info("[CACHE] [ADMIN] New client connection from {}", clientSocket.getRemoteSocketAddress());
            
            BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            
            // Read the request line
            String requestLine = reader.readLine();
            if (requestLine == null) {
                LOGGER.warn("[CACHE] [ADMIN] Null request line from {}", clientSocket.getRemoteSocketAddress());
                sendErrorResponse(clientSocket, 400, "Bad Request");
                return;
            }
            
            LOGGER.info("[CACHE] [ADMIN] Request: {}", requestLine);
            
            // Parse the request line
            String[] parts = requestLine.split(" ");
            if (parts.length != 3) {
                LOGGER.warn("[CACHE] [ADMIN] Invalid request line: {}", requestLine);
                sendErrorResponse(clientSocket, 400, "Bad Request");
                return;
            }
            
            String method = parts[0];
            String path = parts[1];
            
            LOGGER.info("[CACHE] [ADMIN] Method: {}, Path: {}", method, path);
            
            // Read headers
            Map<String, String> headers = new HashMap<>();
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                int colonPos = line.indexOf(':');
                if (colonPos > 0) {
                    String key = line.substring(0, colonPos).trim().toLowerCase();
                    String value = line.substring(colonPos + 1).trim();
                    headers.put(key, value);
                    LOGGER.info("[CACHE] [ADMIN] Header: '{}' = '{}'", key, value);
                }
            }
            
            // Handle different endpoints
            if (path.startsWith("/cache/populate")) {
                LOGGER.info("[CACHE] [ADMIN] Handling cache populate request");
                handleCachePopulate(clientSocket, method, headers, reader);
            } else if (path.startsWith("/cache/status")) {
                LOGGER.info("[CACHE] [ADMIN] Handling cache status request");
                handleCacheStatus(clientSocket);
            } else if (path.startsWith("/cache/clear")) {
                LOGGER.info("[CACHE] [ADMIN] Handling cache clear request");
                handleCacheClear(clientSocket);
            } else {
                LOGGER.warn("[CACHE] [ADMIN] Unknown path: {}", path);
                sendErrorResponse(clientSocket, 404, "Not Found");
            }
        } catch (IOException e) {
            LOGGER.error("[CACHE] Error handling client connection: {}", e.getMessage());
            try {
                sendErrorResponse(clientSocket, 500, "Internal Server Error");
            } catch (IOException ex) {
                LOGGER.error("[CACHE] Error sending error response: {}", ex.getMessage());
            }
        } finally {
            // Always close the socket when done
            try {
                clientSocket.close();
            } catch (IOException e) {
                LOGGER.error("[CACHE] Error closing client socket: {}", e.getMessage());
            }
        }
    }
    
    private void sendErrorResponse(Socket clientSocket, int statusCode, String statusMessage) throws IOException {
        PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);
        writer.println("HTTP/1.1 " + statusCode + " " + statusMessage);
        writer.println("Content-Type: text/plain");
        writer.println("Content-Length: " + statusMessage.length());
        writer.println("Connection: close");
        writer.println();
        writer.println(statusMessage);
    }
    
    private void sendSuccessResponse(Socket clientSocket, String contentType, String content) throws IOException {
        PrintWriter writer = new PrintWriter(clientSocket.getOutputStream(), true);
        writer.println("HTTP/1.1 200 OK");
        writer.println("Content-Type: " + contentType);
        writer.println("Content-Length: " + content.length());
        writer.println("Connection: close");
        writer.println();
        writer.println(content);
    }
    
    private void handleCachePopulate(Socket clientSocket, String method, Map<String, String> headers, BufferedReader reader) throws IOException {
        LOGGER.info("[CACHE] [ADMIN] Starting cache population request handling");
        
        // Increase socket timeout for large uploads
        clientSocket.setSoTimeout(10 * 60 * 1000); // 10 minutes
        
        if (!"POST".equals(method)) {
            LOGGER.warn("[CACHE] [ADMIN] Method not allowed: {}", method);
            sendErrorResponse(clientSocket, 405, "Method Not Allowed");
            return;
        }
        
        // Get required headers
        String host = headers.get("host");
        String targetPath = headers.get("target-path");
        String contentType = headers.get("content-type");
        String contentLengthStr = headers.get("content-length");
        String transferEncoding = headers.get("transfer-encoding");
        boolean isChunked = "chunked".equalsIgnoreCase(transferEncoding);
        
        LOGGER.info("[CACHE] [ADMIN] Cache populate headers: host={}, targetPath={}, contentType={}, contentLength={}, transferEncoding={}", 
                   host, targetPath, contentType, contentLengthStr, transferEncoding);
        
        if (host == null || targetPath == null || contentType == null) {
            LOGGER.warn("[CACHE] [ADMIN] Missing required headers for cache population");
            sendErrorResponse(clientSocket, 400, "Missing required headers: host, target-path, and content-type are required");
            return;
        }
        
        // For non-chunked requests, we need content-length
        int contentLength = -1;
        if (!isChunked && contentLengthStr == null) {
            LOGGER.warn("[CACHE] [ADMIN] Missing Content-Length header for non-chunked request");
            sendErrorResponse(clientSocket, 400, "Missing Content-Length header");
            return;
        }
        
        if (contentLengthStr != null) {
            try {
                contentLength = Integer.parseInt(contentLengthStr);
                LOGGER.info("[CACHE] [ADMIN] Content length: {} bytes", contentLength);
            } catch (NumberFormatException e) {
                LOGGER.warn("[CACHE] [ADMIN] Invalid content length: {}", contentLengthStr);
                sendErrorResponse(clientSocket, 400, "Invalid Content-Length");
                return;
            }
        }
        
        // Get raw input stream for binary data
        InputStream rawInputStream = clientSocket.getInputStream();
        
        // Read the request body directly as binary
        LOGGER.info("[CACHE] [ADMIN] Starting to read binary request body");
        ByteArrayOutputStream contentBuffer = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int bytesRead;
        int totalBytesRead = 0;
        long startTime = System.currentTimeMillis();
    
        try {
            if (isChunked) {
                LOGGER.info("[CACHE] [ADMIN] Reading chunked encoded data");
                // Handle chunked encoding
                // First, consume any remaining data in the reader's buffer
                while (reader.ready()) {
                    reader.read();
                }
            
                // Now read the chunked data
                int chunkSize;
                String line;
                BufferedReader chunkReader = new BufferedReader(new InputStreamReader(rawInputStream));
                
                // Read chunk size line
                while ((line = chunkReader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty()) continue; // Skip empty lines
                    
                    // Parse chunk size (in hex)
                    int idx = line.indexOf(';');
                    if (idx >= 0) {
                        line = line.substring(0, idx);
                    }
                    
                    try {
                        chunkSize = Integer.parseInt(line, 16);
                    } catch (NumberFormatException e) {
                        LOGGER.error("[CACHE] [ADMIN] Invalid chunk size: {}", line);
                        sendErrorResponse(clientSocket, 400, "Invalid chunk size");
                        return;
                    }
                    
                    LOGGER.info("[CACHE] [ADMIN] Reading chunk of size: {} bytes", chunkSize);
                    
                    if (chunkSize == 0) {
                        // Last chunk
                        break;
                    }
                    
                    // Read chunk data
                    int remaining = chunkSize;
                    while (remaining > 0) {
                        int toRead = Math.min(buffer.length, remaining);
                        bytesRead = rawInputStream.read(buffer, 0, toRead);
                        
                        if (bytesRead == -1) {
                            LOGGER.error("[CACHE] [ADMIN] Unexpected end of stream while reading chunk");
                            sendErrorResponse(clientSocket, 400, "Unexpected end of stream");
                            return;
                        }
                        
                        contentBuffer.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                        remaining -= bytesRead;
                        
                        // Log progress every 1MB
                        if (totalBytesRead % (1024 * 1024) < 8192) {
                            LOGGER.info("[CACHE] [ADMIN] Read progress: {} bytes", totalBytesRead);
                        }
                    }
                    
                    // Read and discard CRLF after chunk data
                    chunkReader.readLine();
                }
                
                // Read and discard trailing headers (if any)
                while ((line = chunkReader.readLine()) != null && !line.isEmpty()) {
                    // Just discard
                }
            } else {
                // Handle normal content-length encoding
                // First, consume any remaining data in the reader's buffer
                while (reader.ready()) {
                    reader.read();
                }
                
                // Now read the binary data directly
                while (totalBytesRead < contentLength && (bytesRead = rawInputStream.read(buffer)) != -1) {
                    contentBuffer.write(buffer, 0, bytesRead);
                    totalBytesRead += bytesRead;
                    
                    // Log progress every 1MB
                    if (totalBytesRead % (1024 * 1024) < 8192) {
                        LOGGER.info("[CACHE] [ADMIN] Read progress: {}/{} bytes ({} %)", 
                                   totalBytesRead, contentLength, 
                                   (int)((totalBytesRead * 100.0) / contentLength));
                    }
                }
                
                if (totalBytesRead < contentLength) {
                    LOGGER.warn("[CACHE] [ADMIN] Incomplete request body: {} of {} bytes", 
                               totalBytesRead, contentLength);
                    sendErrorResponse(clientSocket, 400, "Incomplete request body");
                    return;
                }
            }
            
            long elapsedMs = System.currentTimeMillis() - startTime;
            LOGGER.info("[CACHE] [ADMIN] Finished reading request body: {} bytes in {} ms ({} KB/s)", 
                       totalBytesRead, elapsedMs, 
                       (totalBytesRead / 1024.0) / (elapsedMs / 1000.0));
            
            // Create a URL for the target
            String url = "http://" + host + targetPath;
            LOGGER.info("[CACHE] [ADMIN] Target URL for cache: {}", url);
            
            // Create a cache entry
            byte[] content = contentBuffer.toByteArray();
            CacheEntry entry = new CacheEntry(content, contentType, null, null);
            
            // Generate cache key and save to disk
            String cacheKey = generateCacheKey(url);
            LOGGER.info("[CACHE] [ADMIN] Generated cache key: {}", cacheKey);
            
            try {
                saveToDisk(cacheKey, entry);
                LOGGER.info("[CACHE] [ADMIN] Successfully saved to disk: {} ({} bytes)", cacheKey, content.length);
            } catch (Exception e) {
                LOGGER.error("[CACHE] [ADMIN] Error saving to disk: {}", e.getMessage(), e);
                sendErrorResponse(clientSocket, 500, "Error saving to cache");
                return;
            }
            
            LOGGER.info("[CACHE] [ADMIN] Manually populated cache for URL: {} ({} bytes)", url, content.length);
            
            // Send success response
            sendSuccessResponse(clientSocket, "application/json", "{\"status\":\"success\",\"message\":\"Cache populated successfully\",\"url\":\"" + url + "\",\"size\":" + content.length + "}");
            
        } catch (IOException e) {
            LOGGER.error("[CACHE] [ADMIN] Error reading request body: {}", e.getMessage(), e);
            sendErrorResponse(clientSocket, 500, "Error reading request body: " + e.getMessage());
        }
    }
    
    private void handleCacheStatus(Socket clientSocket) throws IOException {
        // Count cache entries and total size
        int entryCount = 0;
        long totalSize = 0;
        
        try {
            if (Files.exists(cacheDir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(cacheDir)) {
                    for (Path entry : stream) {
                        if (Files.isRegularFile(entry)) {
                            entryCount++;
                            totalSize += Files.size(entry);
                        }
                    }
                }
            }
        } catch (IOException e) {
            LOGGER.error("[CACHE] Error getting cache status: {}", e.getMessage());
            sendErrorResponse(clientSocket, 500, "Error getting cache status");
            return;
        }
        
        // Format response
        String response = String.format("{\"status\":\"success\",\"entries\":%d,\"size\":%d,\"sizeFormatted\":\"%s\"}", 
                entryCount, totalSize, formatSize(totalSize));
        
        sendSuccessResponse(clientSocket, "application/json", response);
    }
    
    private void handleCacheClear(Socket clientSocket) throws IOException {
        int deletedCount = 0;
        
        try {
            if (Files.exists(cacheDir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(cacheDir)) {
                    for (Path entry : stream) {
                        if (Files.isRegularFile(entry)) {
                            Files.delete(entry);
                            deletedCount++;
                        }
                    }
                }
            }
            
            LOGGER.info("[CACHE] Cache cleared: {} entries deleted", deletedCount);
            sendSuccessResponse(clientSocket, "application/json", "{\"status\":\"success\",\"message\":\"Cache cleared\",\"deletedEntries\":" + deletedCount + "}");
        } catch (IOException e) {
            LOGGER.error("[CACHE] Error clearing cache: {}", e.getMessage());
            sendErrorResponse(clientSocket, 500, "Error clearing cache");
        }
    }
    
    private String formatSize(long bytes) {
        final String[] units = new String[] { "B", "KB", "MB", "GB", "TB" };
        int unitIndex = 0;
        double size = bytes;
        
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }
        
        return String.format("%.2f %s", size, units[unitIndex]);
    }

    @Override
    public void onProxyInitialization(@NotNull ProxyServer proxy) {
        startAdminServer();
        
        // Register shutdown hook to stop admin server
        Runtime.getRuntime().addShutdownHook(new Thread(this::stopAdminServer));
        try {
            // Initialize cache directory
            cacheDir = Paths.get("/data/data/io.github.krlvm.powertunnel.android.dev/cache/powertunnel");
            Files.createDirectories(cacheDir);
            LOGGER.info("[CACHE] Initialized cache directory: {} ===", cacheDir);
            
            // Enable full response collection to ensure we get all chunks
            proxy.setFullResponse(true);
            LOGGER.info("[CACHE] Enabled full response collection ===");

            registerProxyListener(new ProxyAdapter() {
                // Override to control chunk size
                @Override
                public Integer onGetChunkSize(@NotNull FullAddress address) {
                    // Use default chunk size
                    return null;
                }
                
                // Override to ensure full chunking for cacheable requests
                @Override
                public Boolean isFullChunking(@NotNull FullAddress address) {
                    // Enable full chunking for all requests
                    return true;
                }
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
                        // Get the proxy server first, then use its response builder
                        ProxyResponse response = getServer().getProxyServer().getResponseBuilder(new String(entry.content, StandardCharsets.UTF_8))
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
                    if (currentRequest == null) return;
                    String fullUrl = getFullUrl(currentRequest);
                    LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse for {} ===", fullUrl);
                    
                    // Skip processing for non-cacheable requests
                    if (!isCacheable(currentRequest)) {
                        LOGGER.warn("[CACHE] Skipping non-cacheable request in onServerToProxyResponse: {} ===", fullUrl);
                        return;
                    }
                    
                    try {
                        // Initialize buffer if needed
                        if (!chunkBuffers.containsKey(fullUrl)) {
                            chunkBuffers.put(fullUrl, new ByteArrayOutputStream());
                        }
                        
                        // Store response headers (case-insensitive)
                        Map<String, String> headers = new HashMap<>();
                        for (String name : response.headers().names()) {
                            // Store both original case and lowercase version for lookup
                            headers.put(name.toLowerCase(), response.headers().get(name));
                            headers.put(name, response.headers().get(name));
                        }
                        responseHeaders.put(fullUrl, headers);
                        
                        // Try to extract content regardless of isDataPacket result
                        try {
                            // First try: standard content extraction
                            try {
                                byte[] content = response.content();
                                if (content != null && content.length > 0) {
                                    LOGGER.warn("[CACHE] [3/4] Got {} bytes from standard content() ===", content.length);
                                    chunkBuffers.get(fullUrl).write(content);
                                    LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                                    return;
                                } else {
                                    LOGGER.warn("[CACHE] [3/4] Standard content extraction returned empty or null ===");
                                }
                            } catch (Exception e) {
                                LOGGER.warn("[CACHE] [3/4] Error getting content via standard method: {} ===", e.getMessage());
                            }
                            
                            // Second try: reflection to access httpObject
                            try {
                                java.lang.reflect.Method method = response.getClass().getMethod("getLittleProxyObject");
                                Object httpObject = method.invoke(response);
                                LOGGER.warn("[CACHE] [3/4] Got httpObject using getLittleProxyObject: {} ===", 
                                            httpObject != null ? httpObject.getClass().getName() : "null");
                                
                                if (httpObject instanceof io.netty.handler.codec.http.HttpContent) {
                                    io.netty.handler.codec.http.HttpContent httpContent = (io.netty.handler.codec.http.HttpContent) httpObject;
                                    io.netty.buffer.ByteBuf buf = httpContent.content();
                                    if (buf != null && buf.readableBytes() > 0) {
                                        byte[] bytes = new byte[buf.readableBytes()];
                                        buf.getBytes(buf.readerIndex(), bytes);
                                        LOGGER.warn("[CACHE] [3/4] Got {} bytes from HttpContent ===", bytes.length);
                                        chunkBuffers.get(fullUrl).write(bytes);
                                        LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                                        return;
                                    }
                                } else if (httpObject instanceof io.netty.handler.codec.http.FullHttpResponse) {
                                    io.netty.handler.codec.http.FullHttpResponse fullResponse = (io.netty.handler.codec.http.FullHttpResponse) httpObject;
                                    io.netty.buffer.ByteBuf buf = fullResponse.content();
                                    if (buf != null && buf.readableBytes() > 0) {
                                        byte[] bytes = new byte[buf.readableBytes()];
                                        buf.getBytes(buf.readerIndex(), bytes);
                                        LOGGER.warn("[CACHE] [3/4] Got {} bytes from FullHttpResponse ===", bytes.length);
                                        chunkBuffers.get(fullUrl).write(bytes);
                                        LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                                        return;
                                    }
                                }
                            } catch (Exception e) {
                                LOGGER.warn("[CACHE] [3/4] Error using getLittleProxyObject: {} ===", e.getMessage());
                            }
                            
                            // Third try: examine fields directly
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
                                                    LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                                                    return;
                                                }
                                            } else if (fieldValue instanceof io.netty.buffer.ByteBuf) {
                                                io.netty.buffer.ByteBuf buf = (io.netty.buffer.ByteBuf) fieldValue;
                                                if (buf.readableBytes() > 0) {
                                                    byte[] bytes = new byte[buf.readableBytes()];
                                                    buf.getBytes(buf.readerIndex(), bytes);
                                                    LOGGER.warn("[CACHE] [3/4] Got {} bytes from ByteBuf field {} ===", bytes.length, fieldName);
                                                    chunkBuffers.get(fullUrl).write(bytes);
                                                    LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                                                    return;
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
                            
                            // Check for Transfer-Encoding: chunked header
                            String transferEncoding = response.headers().get("Transfer-Encoding");
                            if (transferEncoding != null && transferEncoding.equalsIgnoreCase("chunked")) {
                                LOGGER.warn("[CACHE] [3/4] Detected chunked encoding, will try to extract in onProxyToClientResponse ===");
                                // For chunked responses, we'll try again in onProxyToClientResponse
                                LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                                return;
                            }
                            
                            LOGGER.warn("[CACHE] [3/4] Failed to extract content, will try again in onProxyToClientResponse ===");
                        } catch (Exception e) {
                            LOGGER.error("[CACHE] [3/4] Error extracting content: {} ===", e.getMessage());
                        }

                        LOGGER.warn("[CACHE] [3/4] onServerToProxyResponse EXIT ===");
                    } catch (Exception e) {
                        LOGGER.error("[CACHE] Error in onServerToProxyResponse: {} ===", e.getMessage(), e);
                        cleanup(getFullUrl(currentRequest));
                    }
                }

                @Override
                public void onProxyToClientResponse(@NotNull ProxyResponse response) {
                    if (currentRequest == null) return;
                    String fullUrl = getFullUrl(currentRequest);
                    LOGGER.warn("[CACHE] [4/4] onProxyToClientResponse for {} ===", fullUrl);
                    
                    // Skip processing for non-cacheable requests
                    if (!isCacheable(currentRequest)) {
                        LOGGER.warn("[CACHE] Skipping non-cacheable request in onProxyToClientResponse: {} ===", fullUrl);
                        return;
                    }
                    
                    try {
                        // Check if we have buffered content and headers
                        if (!chunkBuffers.containsKey(fullUrl) || !responseHeaders.containsKey(fullUrl)) {
                            LOGGER.warn("[CACHE] [4/4] No buffered content or headers for {} ===", fullUrl);
                            return;
                        }
                        
                        Map<String, String> headers = responseHeaders.get(fullUrl);
                        ByteArrayOutputStream buffer = chunkBuffers.get(fullUrl);
                        
                        // Try to extract content if buffer is empty
                        if (buffer.size() == 0) {
                            try {
                                // First try: standard content extraction
                                try {
                                    byte[] content = response.content();
                                    if (content != null && content.length > 0) {
                                        LOGGER.warn("[CACHE] [4/4] Got {} bytes from standard content() in final stage ===", content.length);
                                        buffer.write(content);
                                    } else {
                                        LOGGER.warn("[CACHE] [4/4] Standard content extraction returned empty or null in final stage ===");
                                    }
                                } catch (Exception e) {
                                    LOGGER.warn("[CACHE] [4/4] Error getting content via standard method in final stage: {} ===", e.getMessage());
                                }
                                
                                // Second try: reflection to access httpObject
                                try {
                                    java.lang.reflect.Method method = response.getClass().getMethod("getLittleProxyObject");
                                    Object httpObject = method.invoke(response);
                                    LOGGER.warn("[CACHE] [4/4] Got httpObject using getLittleProxyObject: {} ===", 
                                                httpObject != null ? httpObject.getClass().getName() : "null");
                                    
                                    if (httpObject instanceof io.netty.handler.codec.http.HttpContent) {
                                        io.netty.handler.codec.http.HttpContent httpContent = (io.netty.handler.codec.http.HttpContent) httpObject;
                                        io.netty.buffer.ByteBuf buf = httpContent.content();
                                        if (buf != null && buf.readableBytes() > 0) {
                                            byte[] bytes = new byte[buf.readableBytes()];
                                            buf.getBytes(buf.readerIndex(), bytes);
                                            LOGGER.warn("[CACHE] [4/4] Got {} bytes from HttpContent in final stage ===", bytes.length);
                                            buffer.write(bytes);
                                        }
                                    } else if (httpObject instanceof io.netty.handler.codec.http.FullHttpResponse) {
                                        io.netty.handler.codec.http.FullHttpResponse fullResponse = (io.netty.handler.codec.http.FullHttpResponse) httpObject;
                                        io.netty.buffer.ByteBuf buf = fullResponse.content();
                                        if (buf != null && buf.readableBytes() > 0) {
                                            byte[] bytes = new byte[buf.readableBytes()];
                                            buf.getBytes(buf.readerIndex(), bytes);
                                            LOGGER.warn("[CACHE] [4/4] Got {} bytes from FullHttpResponse in final stage ===", bytes.length);
                                            buffer.write(bytes);
                                        }
                                    }
                                } catch (Exception e) {
                                    LOGGER.warn("[CACHE] [4/4] Error using getLittleProxyObject in final stage: {} ===", e.getMessage());
                                }
                                
                                // Third try: examine fields directly
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
                                                    }
                                                } else if (fieldValue instanceof io.netty.buffer.ByteBuf) {
                                                    io.netty.buffer.ByteBuf buf = (io.netty.buffer.ByteBuf) fieldValue;
                                                    if (buf.readableBytes() > 0) {
                                                        byte[] bytes = new byte[buf.readableBytes()];
                                                        buf.getBytes(buf.readerIndex(), bytes);
                                                        LOGGER.warn("[CACHE] [4/4] Got {} bytes from ByteBuf field {} ===", bytes.length, fieldName);
                                                        buffer.write(bytes);
                                                    }
                                                }
                                            }
                                        } catch (Exception e) {
                                            LOGGER.warn("[CACHE] [4/4] Error accessing field {}: {} ===", fieldName, e.getMessage());
                                        }
                                    }
                                } catch (Exception e) {
                                    LOGGER.error("[CACHE] [4/4] Error getting content via reflection in final stage: {} ===", e.getMessage());
                                }
                            } catch (Exception e) {
                                LOGGER.error("[CACHE] [4/4] Error getting content in final stage: {} ===", e.getMessage());
                            }
                        }
                        
                        byte[] finalContent = buffer.toByteArray();
                        
                        // If we have chunk data for this URL, use it instead
                        if (chunkData.containsKey(fullUrl) && chunkData.get(fullUrl).size() > 0) {
                            finalContent = chunkData.get(fullUrl).toByteArray();
                            LOGGER.warn("[CACHE] Using {} bytes from chunk data instead of buffer ===", finalContent.length);
                        }
                        
                        LOGGER.warn("[CACHE] Final content size: {} bytes ===", finalContent.length);

                        if (finalContent.length == 0) {
                            LOGGER.error("[CACHE] Empty response body after buffering ===");
                            cleanup(fullUrl);
                            return;
                        }

                        // Case-insensitive header lookup
                        String contentType = headers.get("content-type");
                        String contentEncoding = headers.get("content-encoding");
                        String etag = headers.get("etag");
                        
                        LOGGER.warn("[CACHE] Headers map contains {} entries ===", headers.size());
                        for (Map.Entry<String, String> entry : headers.entrySet()) {
                            LOGGER.warn("[CACHE] Header: '{}' = '{}' ===", entry.getKey(), entry.getValue());
                        }

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
