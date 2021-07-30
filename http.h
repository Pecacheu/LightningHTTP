//LightningHTTP v3.6.1 ©2021 Pecacheu; GNU GPL 3.0
#pragma once

#include <utils.h>
#include <net.h>

#define HTTP_DEBUG 0
#define HTTP_VERSION "3.6.1"
#define HTTP_BACKLOG 50 //Pending Connection Buffer
#define HTTP_THREADS 1000 //Max Cients
#define HTTP_TIMEOUT 15
#define HTTP_READ_SIZE 4096
#define HTTP_NEWLINE "\r\n"
#define HTTP_POST_MAX 1048576 //1MB

//Global Header Behavior:
#define HTTP_SEND_NAME //Include PC name in 'Server' header
#define HTTP_NO_CORS //Prevent iframe loading & CORS attacks

namespace http {
using namespace net;

struct HttpRequest; class HttpSocket; class HttpResponse;
typedef function<void(int err, HttpRequest *res, string *eMsg)> HttpResFunc;
typedef function<void(HttpRequest& req, HttpResponse& res)> HttpReqFunc;
typedef function<char(HttpSocket& sck, HttpRequest *req, HttpResponse *err)> HttpPreFunc;

struct HttpOptions {
	HttpReqFunc onRequest=0; HttpPreFunc preRequest=0;
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
	HttpSocket(HttpServer& s, Socket c); HttpSocket(Socket c);
	void init(); bool initCli(bool https, HttpResFunc& cb);
	ssize_t write(Buffer b);
	private: void cclose(); char run(char *b); char parse(Buffer b);
	char bCopy(const char *buf, size_t len, size_t *rs=0);
	char parseChunk(const char *buf, size_t len);
	ssize_t read(char *buf, size_t len);
	void sendCode(uint16_t code, string msg);
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