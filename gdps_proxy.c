#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>

#define PORT 3000
#define BUFFER_SIZE 65536
#define GDPS_URL "https://gdps.dimisaio.be/database/"
#define DATA_FILE "/var/mobile/Documents/gdps_data.txt"

static char cached_gjp2[64] = {0};

// Forward declaration
void* server_main(void *arg);

// SHA1 hash function for GJP2
void compute_gjp2(const char *password, char *output) {
    char input[256];
    snprintf(input, sizeof(input), "%smI29fmAnxgTs", password);
    
    unsigned char hash[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(input, strlen(input), hash);
    
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[CC_SHA1_DIGEST_LENGTH * 2] = '\0';
}

// Load cached GJP2 from file
void load_cached_gjp2() {
    FILE *f = fopen(DATA_FILE, "r");
    if (f) {
        if (fgets(cached_gjp2, sizeof(cached_gjp2), f)) {
            cached_gjp2[strcspn(cached_gjp2, "\n")] = 0;
        }
        fclose(f);
    }
}

// Save GJP2 to file
void save_gjp2(const char *gjp2) {
    FILE *f = fopen(DATA_FILE, "w");
    if (f) {
        fprintf(f, "%s", gjp2);
        fclose(f);
        strcpy(cached_gjp2, gjp2);
    }
}

// URL encode helper
void url_encode(const char *src, char *dst, size_t dst_size) {
    const char *hex = "0123456789ABCDEF";
    size_t pos = 0;
    
    for (; *src && pos < dst_size - 4; src++) {
        if (isalnum(*src) || *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dst[pos++] = *src;
        } else if (*src == ' ') {
            dst[pos++] = '+';
        } else {
            dst[pos++] = '%';
            dst[pos++] = hex[(*src >> 4) & 0xF];
            dst[pos++] = hex[*src & 0xF];
        }
    }
    dst[pos] = '\0';
}

// URL decode helper
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

// Extract value from POST data
char* extract_param(const char *data, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "%s=", key);
    char *pos = strstr(data, search);
    if (!pos) return NULL;
    
    pos += strlen(search);
    char *end = strchr(pos, '&');
    size_t len = end ? (end - pos) : strlen(pos);
    
    char *result = malloc(len + 1);
    strncpy(result, pos, len);
    result[len] = '\0';
    
    char *decoded = malloc(len + 1);
    url_decode(decoded, result);
    free(result);
    
    return decoded;
}

// Simple HTTPS POST using CFNetwork
char* https_post(const char *url, const char *post_data) {
    CFStringRef urlString = CFStringCreateWithCString(NULL, url, kCFStringEncodingUTF8);
    CFURLRef cfUrl = CFURLCreateWithString(NULL, urlString, NULL);
    CFRelease(urlString);
    
    if (!cfUrl) return strdup("-1");
    
    // Create request
    CFStringRef method = CFSTR("POST");
    CFHTTPMessageRef request = CFHTTPMessageCreateRequest(NULL, method, cfUrl, kCFHTTPVersion1_1);
    CFRelease(cfUrl);
    
    if (!request) return strdup("-1");
    
    // Set headers
    CFStringRef contentType = CFSTR("application/x-www-form-urlencoded");
    CFHTTPMessageSetHeaderFieldValue(request, CFSTR("Content-Type"), contentType);
    
    // Set body
    CFDataRef bodyData = CFDataCreate(NULL, (const UInt8*)post_data, strlen(post_data));
    CFHTTPMessageSetBody(request, bodyData);
    CFRelease(bodyData);
    
    // Create read stream
    CFReadStreamRef readStream = CFReadStreamCreateForHTTPRequest(NULL, request);
    CFRelease(request);
    
    if (!readStream) return strdup("-1");
    
    // Enable automatic redirect and SSL
    CFReadStreamSetProperty(readStream, kCFStreamPropertyHTTPShouldAutoredirect, kCFBooleanTrue);
    
    // Open stream
    if (!CFReadStreamOpen(readStream)) {
        CFRelease(readStream);
        return strdup("-1");
    }
    
    // Read response
    CFMutableDataRef responseData = CFDataCreateMutable(NULL, 0);
    UInt8 buffer[8192];
    CFIndex bytesRead;
    
    while ((bytesRead = CFReadStreamRead(readStream, buffer, sizeof(buffer))) > 0) {
        CFDataAppendBytes(responseData, buffer, bytesRead);
    }
    
    CFReadStreamClose(readStream);
    CFRelease(readStream);
    
    // Convert to C string
    CFIndex length = CFDataGetLength(responseData);
    char *result = malloc(length + 1);
    CFDataGetBytes(responseData, CFRangeMake(0, length), (UInt8*)result);
    result[length] = '\0';
    CFRelease(responseData);
    
    // Extract body from HTTP response
    char *body = strstr(result, "\r\n\r\n");
    if (body) {
        body += 4;
        char *final = strdup(body);
        free(result);
        return final;
    }
    
    return result;
}

// Handle client connection
void* handle_client(void *arg) {
    int client_sock = *(int*)arg;
    free(arg);
    
    char buffer[BUFFER_SIZE];
    int received = recv(client_sock, buffer, BUFFER_SIZE - 1, 0);
    if (received <= 0) {
        close(client_sock);
        return NULL;
    }
    buffer[received] = '\0';
    
    // Parse HTTP request
    char method[16], path[512], version[16];
    sscanf(buffer, "%s %s %s", method, path, version);
    
    // Find POST data
    char *body_start = strstr(buffer, "\r\n\r\n");
    char *post_data = body_start ? body_start + 4 : "";
    
    // Build full URL
    char full_url[1024];
    snprintf(full_url, sizeof(full_url), "%s%s", GDPS_URL, path + 1); // +1 to skip leading /
    
    // Add GJP2 if accountID is present
    char modified_post[BUFFER_SIZE];
    strcpy(modified_post, post_data);
    if (strstr(post_data, "accountID") && cached_gjp2[0]) {
        snprintf(modified_post, sizeof(modified_post), "%s&gjp2=%s", post_data, cached_gjp2);
    }
    
    // Handle login
    if (strstr(path, "loginGJAccount.php")) {
        char *password = extract_param(post_data, "password");
        if (password) {
            char gjp2[64];
            compute_gjp2(password, gjp2);
            save_gjp2(gjp2);
            free(password);
        }
    }
    
    // Make request
    char *response_body = https_post(full_url, modified_post);
    if (!response_body) response_body = strdup("-1");
    
    // Send HTTP response
    char http_response[BUFFER_SIZE];
    int response_len = snprintf(http_response, sizeof(http_response),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=UTF-8\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n%s", strlen(response_body), response_body);
    
    send(client_sock, http_response, response_len, 0);
    
    free(response_body);
    close(client_sock);
    return NULL;
}

// Start HTTP server
__attribute__((constructor))
static void start_server() {
    pthread_t thread;
    pthread_create(&thread, NULL, server_main, NULL);
    pthread_detach(thread);
}

void* server_main(void *arg) {
    load_cached_gjp2();
    
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) return NULL;
    
    int opt = 1;
    setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_sock);
        return NULL;
    }
    
    listen(server_sock, 5);
    printf("GDPS Proxy started on port %d\n", PORT);
    
    while (1) {
        int *client_sock = malloc(sizeof(int));
        *client_sock = accept(server_sock, NULL, NULL);
        if (*client_sock < 0) {
            free(client_sock);
            continue;
        }
        
        pthread_t client_thread;
        pthread_create(&client_thread, NULL, handle_client, client_sock);
        pthread_detach(client_thread);
    }
    
    return NULL;
}
