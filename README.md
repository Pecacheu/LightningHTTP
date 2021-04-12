# LightningHTTP
High performance minimal C++ HTTP Server w/ HTTPS Support

### Dependencies:
- C++14 & std library (including std::thread)
- C++ utils.h & net.h
- OpenSSL 1.1 or later
- Optional: Linux sys/utsname.h

### Server Dependencies:
- std::fstream (File read/write)
- C++14 filesystem (General fs access. Can also use boost.filesystem)
- Unix sys/inotify.h (Tracks filesystem changes)

## Namespace: http

### Macros
- `HTTP_DEBUG` 0 = Disabled, 1 = Debug, 2 = Verbose Debug, 3 = Verbose Debug & Print all data
- `HTTP_VERSION` Library version.
- `HTTP_BACKLOG` Set pending connection buffer.
- `HTTP_THREADS` Set max clients.
- `HTTP_TIMEOUT` Set thread timeout in seconds.
- `HTTP_READ_SIZE` Set read buffer size.
- `HTTP_NEWLINE` Do not change.
- `HTTP_POST_MAX` Maximum POST data length.

### Global Header Behavior
- `HTTP_SEND_NAME` Include PC name in 'Server' header.
- `HTTP_NO_CORS` Prevent iframe loading & CORS attacks.

### Typedefs
- HttpResFunc `void func(int err, HttpRequest *res, string *eMsg)` HTTP Response callback.

### Functions
- `string httpGetVersion()` Get version string.
- `HttpServer *httpStartServer(uint16_t port, string name, HttpOptions& opt, SSLList *sl=0)` Start server `name` listening at `port`. If `sl` is provided, the server uses HTTPS.
- `HttpResponse *httpOpenRequest(NetAddr a, HttpResFunc cb, bool https=0)` Open a request to address `a` with callback `cb`. Optionally, you can set request headers and write data via the returned HttpResponse object. Then call `end()` to send the request. *(Note: NetAddr is part of [C-Utils](https://github.com/pecacheu/c-utils).)*

### [struct] HttpOptions
Set server options.
- `void onRequest(HttpRequest& req, HttpResponse& res)` Fired in a dedicated client thread upon receiving a valid HTTP request. Please write all response data and call `res.end()` before exiting the function.
- `char preRequest(HttpSocket& sck, HttpRequest *req, HttpResponse *err)` Fired before request is parsed.
	- `sck` The client socket.
	- `req` Partial request data, including headers, or NULL if there was an error that prevented header parsing.
	- `err` If the server sent back an error, the code and message can be found here. NULL otherwise.
	- The return value controls how the request is handled. *0 = Default, 1 = Skip, 2 = Drop Connection*
	- *Note: Connection will be dropped regardless if there was a data parsing error.*

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
- `void setUseChunked(bool uc)` Enables chunked transfer mode.
- `void setKeepAlive(bool ka)` Sets Connection to keep-alive.
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

### [class] HttpSocket
Represents a client socket. Do not call any functions.
- `HttpServer *srv` The server this socket belongs to.
- `Socket cli` Underlying net::Socket instance.
- `const string& name` Human-readable name for logging purposes.