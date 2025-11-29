// gdproxy.m
// ONE-FILE local HTTP server for iOS 5/6 Geometry Dash
// Zero dependencies except Foundation + CommonCrypto

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <pthread.h>
#import <unistd.h>

static NSString *gjp2_cached = nil;
static NSString *gjp2_path = @"/var/mobile/Library/gjp2.txt";

#pragma mark - GJP2 Hash

NSString *GJP2(NSString *pass) {
    NSString *s = [pass stringByAppendingString:@"mI29fmAnxgTs"];
    NSData *d = [s dataUsingEncoding:NSUTF8StringEncoding];

    uint8_t dig[CC_SHA1_DIGEST_LENGTH];
    CC_SHA1(d.bytes, (CC_LONG)d.length, dig);

    NSMutableString *out = [NSMutableString stringWithCapacity:40];
    for (int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [out appendFormat:@"%02x", dig[i]];

    return out;
}

#pragma mark - Forward POST

NSString *ForwardPOST(NSString *url, NSString *body) {
    NSURL *u = [NSURL URLWithString:
        [@"https://gdps.dimisaio.be/database" stringByAppendingString:url]];

    NSMutableURLRequest *r = [NSMutableURLRequest requestWithURL:u];
    [r setHTTPMethod:@"POST"];
    [r setHTTPBody:[body dataUsingEncoding:NSUTF8StringEncoding]];

    NSData *resp = [NSURLConnection sendSynchronousRequest:r
                                         returningResponse:nil
                                                     error:nil];
    if (!resp) return @"-9";
    return [[[NSString alloc] initWithData:resp
                                  encoding:NSUTF8StringEncoding] autorelease];
}

#pragma mark - Process Request (VB.NET Logic)

NSString *ProcessRequest(NSString *url, NSString *body) {

    // If login request — extract password and save GJP2
    if ([url containsString:@"loginGJAccount.php"]) {
        NSArray *parts = [body componentsSeparatedByString:@"&"];
        NSString *pass = nil;

        for (NSString *p in parts) {
            if ([p hasPrefix:@"password="])
                pass = [p substringFromIndex:9];
        }

        if (pass) {
            gjp2_cached = [GJP2(pass) retain];
            [gjp2_cached writeToFile:gjp2_path
                          atomically:YES
                            encoding:NSUTF8StringEncoding
                               error:nil];
        }
    }

    // If body contains accountID add gjp2
    if ([body containsString:@"accountID"] && gjp2_cached.length > 0) {
        body = [body stringByAppendingFormat:@"&gjp2=%@", gjp2_cached];
    }

    return ForwardPOST(url, body);
}

#pragma mark - Client Handler

void *HandleClient(void *arg) {
    int client = (int)(intptr_t)arg;
    char buf[4096];

    int recvd = recv(client, buf, sizeof(buf)-1, 0);
    if (recvd <= 0) { close(client); return NULL; }
    buf[recvd] = 0;

    // Parse: METHOD URL
    char method[16], url[512];
    sscanf(buf, "%s %s", method, url);

    // Find POST body
    char *b = strstr(buf, "\r\n\r\n");
    NSString *body = @"";

    if (b) {
        b += 4;
        body = [[[NSString alloc] initWithUTF8String:b] autorelease];
    }

    NSString *resp = ProcessRequest(
        [NSString stringWithUTF8String:url],
        body
    );

    NSData *respData = [resp dataUsingEncoding:NSUTF8StringEncoding];

    dprintf(client,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %lu\r\n\r\n",
        (unsigned long)[respData length]
    );
    send(client, [respData bytes], [respData length], 0);

    close(client);
    return NULL;
}

#pragma mark - Server Main Loop

void *ServerThread(void *unused) {
    int s = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(3000);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(s, (struct sockaddr*)&addr, sizeof(addr));
    listen(s, 5);

    // Load stored GJP2 at startup
    gjp2_cached = [[NSString stringWithContentsOfFile:gjp2_path
                                             encoding:NSUTF8StringEncoding
                                                error:nil] retain];

    while (1) {
        int client = accept(s, NULL, NULL);
        pthread_t t;
        pthread_create(&t, NULL, HandleClient, (void*)(intptr_t)client);
        pthread_detach(t);
    }
}

#pragma mark - Auto Start

__attribute__((constructor))
static void start() {
    pthread_t t;
    pthread_create(&t, NULL, ServerThread, NULL);
    pthread_detach(t);
}

