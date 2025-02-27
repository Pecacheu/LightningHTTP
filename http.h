//LightningHTTP ©2025 Pecacheu; GNU GPL 3.0
#pragma once

#include <utils.h>
#include <net.h>

#define HTTP_VERSION "3.7.1"
#define HTTP_NEWLINE "\r\n"

#ifndef HTTP_DEBUG
	#define HTTP_DEBUG 0 //Debug Mode
#endif
#ifndef HTTP_BACKLOG
	#define HTTP_BACKLOG 50 //Pending Connection Buffer
#endif
#ifndef HTTP_THREADS
	#define HTTP_THREADS 1000 //Max Clients
#endif
#ifndef HTTP_TIMEOUT
	#define HTTP_TIMEOUT 15 //Timeout Sec
#endif
#ifndef HTTP_WS_TIMEOUT
	#define HTTP_WS_TIMEOUT 300 //Websocket Timeout Sec
#endif
#ifndef HTTP_READ_SIZE
	#define HTTP_READ_SIZE 8192 //Read Buffer
#endif
#ifndef HTTP_POST_MAX
	#define HTTP_POST_MAX 1074000000 //1GB - Max upload in server mode
#endif
#ifndef HTTP_GET_MAX
	#define HTTP_GET_MAX 1074000000 //1GB - Max download in client mode
#endif
#ifndef HTTP_WS_MAX
	#define HTTP_WS_MAX 1074000000 //1GB - Max WebSocket message size
#endif
#ifndef HTTP_SSL_VERIFY
	#define HTTP_SSL_VERIFY 1 //Verify SSL Certs
#endif

//Global Header Behavior
#ifndef HTTP_SEND_NAME
	#define HTTP_SEND_NAME 1 //Include PC name in 'Server' header
#endif
#ifndef HTTP_NO_CORS
	#define HTTP_NO_CORS 1 //Prevent iframe loading & CORS attacks
#endif

namespace http {
using namespace net;

struct HttpRequest; class HttpSocket; class WebSocket; class HttpResponse;
typedef function<void(int err, HttpRequest *res, string *eMsg)> HttpResFunc;
typedef function<void(HttpRequest& req, HttpResponse& res)> HttpReqFunc;
typedef function<char(HttpSocket& sck, HttpRequest *req, HttpResponse *err)> HttpPreFunc;
typedef function<void(WebSocket& ws)> WSFunc;

struct HttpOptions {
	HttpReqFunc onRequest=0; HttpPreFunc preRequest=0;
	WSFunc onWSConnect=0; WSFunc onWSDisconnect=0;
	map<string, WSFunc> wsPaths;
};

struct SSLList {
	SSLList(size_t l):s(new size_t[l]),h(new string[l]),len(l) {}
	int add(const char *certFile, const char *keyFile, const char *host=0);
	void free(); size_t *s; string *h; size_t len; size_t i=0;
};

struct HttpServer {
	HttpServer(int s, string& n, HttpOptions& o, SSLList *l);
	void stop(); const int s; volatile bool st=0; HttpOptions opt;
	SSLList *sl; volatile size_t tx=0; const string name;
};

string httpGetVersion();
HttpServer *httpStartServer(uint16_t port, string name, HttpOptions& opt, SSLList *sl=0);
HttpResponse *httpOpenRequest(NetAddr a, HttpResFunc cb, bool https=0);

struct HttpRequest {
	HttpRequest(HttpSocket& c, string& t, string& u, stringmap& hd, uint16_t cd, Buffer& n);
	HttpSocket& cli; string type,uri,path,query; stringmap header;
	Buffer& content; uint16_t code; void *u=0;
};

class HttpSocket {
	void *ssl=0; Buffer cBuf; size_t cOfs;
	bool chk; HttpRequest *req; HttpResponse *eRes;
	public: HttpServer *srv; Socket cli; const string name;
	HttpSocket(HttpServer& s, Socket& c); HttpSocket(Socket& c);
	WebSocket *init(); bool initCli(bool https, HttpResFunc& cb);
	ssize_t write(Buffer b);
	private: void cclose(); char run(char *b); char parse(Buffer b);
	char bCopy(const char *buf, size_t len, size_t *rs=0);
	char parseChunk(const char *buf, size_t len);
	ssize_t read(char *buf, size_t len);
	void sendCode(uint16_t code, string msg);
};

class WebSocket {
	size_t mOfs=0; bool fin; void *ssl;
	const WSFunc& cb; uint32_t mask;
	public: bool useMask; HttpServer *srv; Socket cli;
	const string name,path; uint8_t op; Buffer msg;
	WebSocket(HttpSocket& s, string& p, void *ssl);
	void init(); void end(); ssize_t send(Buffer b, uint8_t op=1);
	inline void setTimeout(time_t sec) { cli.setTimeout(sec); }
	private: ssize_t read(char *buf, size_t len);
	ssize_t parseHdr(Buffer b); void run(); void cclose();
};

class HttpResponse {
	bool uC=0,ended=0; char gzip=0; uint16_t stat=0;
	const char *cm; stringmap *hdr; string sMsg=""; Buffer cont;
	public: bool kA; HttpSocket& cli;
	HttpResponse(HttpSocket& c, bool k); HttpResponse(HttpSocket& c);
	inline void setGzip(char gz) { if(!stat) gzip=gz; }
	inline void setUseChunked(bool c) { if(!stat && !cont.len) uC=c; }
	inline void setKeepAlive(bool k) { if(!stat) kA=k; }
	inline uint16_t getStat() { return stat; }
	inline string& getStatMsg() { return sMsg; }
	inline stringmap *getHeaders() { return hdr; }
	inline bool isEnded() { return ended; }
	bool sendCode(uint16_t code, string msg, string desc="");
	inline bool writeHead(uint16_t code, stringmap *headers=0) {
		return writeHead(code,"",headers);
	}
	bool writeHead(uint16_t code, string status, stringmap *headers=0);
	bool writeHead(const char *path=0, const char *method=0, stringmap *headers=0);
	bool write(Buffer data); bool end();
	private: Buffer genHeader();
};

}