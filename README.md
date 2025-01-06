# LightningHTTP
High performance minimal C++ HTTP Server w/ HTTPS Support. A ready-to-go implementation of this library [can be found here](https://github.com/Pecacheu/LightningServer).

### Dependencies:
- C++17 & std library (including std::thread)
- [C-Utils](https://github.com/pecacheu/c-utils) v2.2 or later
- OpenSSL v1.1 or later
- *Optional:* Linux sys/utsname.h

### Server Dependencies:
- std::fstream (File read/write)
- C++ filesystem (General fs access. Could use boost.filesystem)
- Unix sys/inotify.h (Tracks filesystem changes)
- *Optional:* Zlib (File compression)

### Wish list, may be coming in the future:
- Setting (in HttpOptions) to allow direct read-from-disk when SmartCache is full
- HTTP/2 implementation
	- Header compression
	- Data streams replace chunked transfer encoding
	- Allows applications to support ahead-of-time content push
- Implement request push in Server lib through some per-file config mechanism (similar to how +HEADER+ works)
- In Server lib, `404.html` file replaces default 404 screen.
- QUIC protocol support

## Namespace: http

### Macros
- `HTTP_DEBUG` 0 = Disabled, 1 = Debug, 2 = Verbose Debug, 3 = Verbose Debug & Print all data
- `HTTP_VERSION` Library version
- `HTTP_BACKLOG` Set pending connection buffer
- `HTTP_THREADS` Set max clients
- `HTTP_TIMEOUT` Set thread timeout in seconds
- `HTTP_READ_SIZE` Set read buffer size
- `HTTP_NEWLINE` Do not change
- `HTTP_POST_MAX` Maximum POST data length

### Global Header Behavior
- `HTTP_SEND_NAME` Include PC name in 'Server' header
- `HTTP_NO_CORS` Prevent iframe loading & CORS attacks

### Typedefs
- HttpResFunc `void func(int err, HttpRequest *res, string *eMsg)` HTTP Response callback.
- WSFunc `void func(WebSocket& ws)` WebSocket callback.

### Functions
- `string httpGetVersion()` Get version string.
- `HttpServer *httpStartServer(uint16_t port, string name, HttpOptions& opt, SSLList *sl=0)` Start server `name` listening at `port`. If `sl` is provided, the server uses HTTPS.
- `HttpResponse *httpOpenRequest(NetAddr a, HttpResFunc cb, bool https=false)` Open a request to address `a` with callback `cb`. Optionally, you can set request headers and write data via the returned HttpResponse object. Then call `end()` to send the request. *(Note: NetAddr is part of [C-Utils](https://github.com/pecacheu/c-utils).)*

### [struct] HttpOptions
Set server options.
- `void onRequest(HttpRequest& req, HttpResponse& res)` Fired in a dedicated client thread upon receiving a valid HTTP request. Please write all response data and call `res.end()` before exiting the function.
- `char preRequest(HttpSocket& sck, HttpRequest *req, HttpResponse *err)` Fired before request is parsed.
	- `sck` The client socket.
	- `req` Partial request data, including headers, or NULL if there was an error that prevented header parsing.
	- `err` If the server sent back an error, the code and message can be found here. NULL otherwise.
	- The return value controls how the request is handled. *0 = Default, 1 = Skip, 2 = Drop Connection*
	- *Note: Connection will be dropped regardless if there was a data parsing error.*
- `void onWSConnect(WebSocket& ws)` Fired when new WebSocket client connects.
- `void onWSDisconnect(WebSocket& ws)` Fired when a WebSocket disconnects.
- `map<string, WSFunc> wsPaths` Listeners in the map are fired when a matching path string (including starting `/`), receives a WebSocket message.

### [struct] SSLList
- `SSLList(size_t l)` Init SSLList with size `l`. Size is fixed, `add()` will fail if it's called more than `l` times.
- `int add(const char *certFile, const char *keyFile, const char *host=0)` Add a cert/key file combo to the list. `host` is optional hostname for cert. Returns negative on error.
- `void free()` Frees the SSL data from memory. *(Don't worry, this is called automatically when the server is stopped.)*

### [struct] HttpServer
Represents a server created with `httpStartServer()`. Do not call constructor.
- `void stop()` Stop the server.
- `const string name` Server name. Read only.
- `volatile size_t tx` Used to track how many clients are connected. Read only.
- `HttpOptions opt` Server options. Read only.

### [struct] HttpRequest
Represents a request from a client (or the server response from httpOpenRequest). Do not call constructor.
- `HttpSocket& cli` The HttpSocket for this request. The HttpServer can be obtained with `cli.srv`.
- `string type` The request type. Currently only *GET* or *POST*.
- `string uri` Full URI of request, including leading `/`.
- `string path` Path of the request.
- `string query` Query string if any, not including leading `?`.
- `stringmap header` Map of request headers, converted to camel case.
- `Buffer content` Request body.
- `uint16_t code` Status code in client mode, 0 in server mode.
- `void *u` Optional user data.

### [class] HttpResponse
Allows you to respond to the client (or send a request from httpOpenRequest). Do not call constructor.
- `void setGzip(uint8_t gz)` Set the Content-Encoding header. *0 = plain, 1 = gzip, 2 = deflate*
- `void setUseChunked(bool u)` Enables chunked transfer mode.
- `void setKeepAlive(bool k)` Sets Connection to keep-alive.
- `uint16_t getStat()` Get status code.
- `string& getStatMsg()` Get status message.
- `stringmap *getHeaders()` Get map of headers, or NULL if none set.
- `bool isEnded()` True if HttpResponse is ended.
- `bool sendCode(uint16_t code, string msg, string desc="")` Convenience function to send an error to the client. `end()` is called automatically.
- `bool writeHead(uint16_t code, stringmap *headers=0)`\
`bool writeHead(uint16_t code, string status, stringmap *headers=0)` Set status code, message, and headers. Server mode only. Returns true on success.
- `bool writeHead(const char *path="/", const char *method="GET", stringmap *headers=0)` Set request path, method, and headers. Client mode only. Returns true on success.
- `bool write(Buffer data)` Write data. Call `writeHead()` first. Returns true on success.
- `bool end()` End response/send request. If `writeHead()` has not been called, default options are used. Returns true on success.
- `HttpSocket& cli` The HttpSocket for this request. The HttpServer can be obtained with `cli.srv`.

*Note: To set multiple cookies in the `Set-Cookie` header, separate them with `&`.*

### [class] HttpSocket
Represents a client socket. Do not call any functions.
- `const HttpServer *srv` The server this socket belongs to.
- `const Socket cli` Underlying client [net::Socket](https://github.com/pecacheu/c-utils?tab=readme-ov-file#struct-socket).
- `const string& name` Human-readable name for logging purposes.

### [class] WebSocket
Represents a WebSocket connection.
- `const HttpServer *srv` The server this socket belongs to.
- `const Socket cli` Underlying client [net::Socket](https://github.com/pecacheu/c-utils?tab=readme-ov-file#struct-socket).
- `const bool useMask` Whether the socket uses masking.
- `const string name` Human-readable name for logging purposes.
- `const string path` URI path of the message.
- `const uint8_t op` Message [opcode](https://en.wikipedia.org/wiki/WebSocket#Opcodes).
- `const Buffer msg` Message contents.
- `ssize_t send(Buffer b, uint8_t op=1)` Send a message, with optional opcode. Returns bytes sent, or error if <= 0.
- `void setTimeout(time_t sec)` Set socket timeout in seconds.
- `void end()` Gracefully close socket (other side is informed before closing).

## Namespace: server
An easy to use built-in web server engine included with LightningHTTP. Includes file parsing, URL parsing, SmartCache (RAM Cache system) with smart compression (only activates when file has a good compression ratio), and rate limiting!

### Constants
- `stringmap ContentTypes` List of built-in HTTP content types. See `server.cpp` for full list.
- `const string *tHtml,*tJs,*tCSS,*tWoff,*tWoff2,*tJpg` Convenient content type macros for use in `readCustom()`.

### [struct] ServerOpt
Used to set WebServer callbacks.
- `bool chkMode=true` Sets if chunked transfer mode is on by default.
- `HttpOptions http` HTTP options and callbacks. If `end()` is not called in *http.onRequest* before the function ends, WebServer attempts to serve the request from the filesystem. This enables overriding only certain requests or under specific conditions (ex. authentication).
- `HttpReqFunc postReq` Called after a request is complete. Useful for logging purposes.
- `void setHdr(HttpRequest& req, HttpResponse& res, stringmap& hd)` Called before the request is sent, allowing you to set custom headers. Does not fire if `onReq()` handled the request.
- `Buffer readCustom(string f, CacheEntry& c, bool *zip)` Custom read callback, called every time a file changes. Return an empty buffer to perform a standard file read, or return a buffer of size `NPOS` to indicate an error.

### [class] WebServer
Represents a web server and it's HTTP/HTTPS instance.
- `WebServer(string dir, size_t cm, ServerOpt& o)` Create a WebServer instance at `dir` is the root directory of the server, `cm` is the maximum file cache size.
- `int init(string name, uint16_t port, uint16_t sPort=0, SSLList *sl=0)` Start the server. `sPort` is an optional HTTPS port, or 0 to disable HTTPS. If `sPort` is set, `sl` is required.
- `void stop()` Stop the server.
- `EventLoop evl` Internal event loop.

### [struct] CacheEntry
**Do not use.** Stores data used by the internal SmartCache system, which caches files to memory and automatically updates whenever a file is changed.

## Custom Templates
Out-of-the-box, WebServer supports a simple template insertion mechanism. Template filenames should start with a `+` symbol, for example `+MyHeader.html`. To include this template in other files (currently only `.html` is supported), use a specially-formatted HTML comment, eg. `<!-- +MyHeader+ -->` or `<!-- +MyHeader.html+ -->`.

## Simple Server Example

```c++
#include <server.h>
#include <unistd.h>
#include <csignal>

#define PORT 80
#define SPORT 443
#define ROOT "./root"

using namespace server;

size_t getRam() {
	return sysconf(_SC_PHYS_PAGES)*sysconf(_SC_PAGE_SIZE);
}
const size_t SystemRam=getRam(), CacheMax=SystemRam/4; //8GB RAM -> 2GB Cache
WebServer *sv;

void onSig(int s) { sv->stop(); }
int main(int argc, char *argv[]) {
	signal(SIGTERM, onSig); signal(SIGINT, onSig);
	cout << "DATE: " << getDate() << ", RAM: " << (SystemRam/1000000)
		<< "MB, Max Cache: " << (CacheMax/1000000) << "MB\n";

	ServerOpt o;
	sv = new WebServer(ROOT,CacheMax,o);

	SSLList sl(1);
	if(ckErr(sl.add("test.crt", "test.key", "example.com"),"Cert Load")) return 1;
	return sv->init("Test",PORT,SPORT,&sl);
}
```