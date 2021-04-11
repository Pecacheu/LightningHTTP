//LightningHTTP ©2020 Pecacheu; GNU GPL 3.0
#pragma once

#include "utils.h"
#include "net.h"
#include <functional>

#define HTTP_DEBUG 0
#define HTTP_VERSION "3.2"
#define HTTP_BACKLOG 50 //Maximum Buffered Clients
#define HTTP_THREADS 1000 //Maximum Cients
#define HTTP_TIMEOUT 15
#define HTTP_READ_SIZE 4096
#define HTTP_NEWLINE "\r\n"
#define HTTP_POST_MAX 1048576 //1MB

//Global Header Behavior:
#define HTTP_SEND_NAME //Include PC name in 'Server' header
#define HTTP_NO_CORS //Prevent iframe loading & CORS attacks

namespace http {

struct HttpRequest; class HttpSocket; class HttpResponse;
typedef function<void(int err, HttpRequest *res, string *eMsg)> HttpResFunc;

struct HttpOptions {
	void (*onRequest)(HttpRequest& req, HttpResponse& resp);
	int (*preRequest)(HttpSocket& sck, HttpRequest *req, HttpResponse *err);
};

struct SSLList {
	SSLList(size_t l):s(new size_t[l]),h(new string[l]),len(l) {}
	int add(const char *certFile, const char *keyFile, const char *host = 0);
	void free(); size_t *s; string *h; size_t len; size_t i=0;
};

struct HttpServer {
	HttpServer(int s, string& n, HttpOptions& o, SSLList *l); void stop();
	int s; volatile bool st=0; volatile uint32_t tx=0;
	HttpOptions opt; SSLList *sl; const string name;
};

string httpGetVersion();
HttpServer *httpStartServer(uint16_t port, string name, HttpOptions& opt, SSLList *sl = 0);
void httpStopServer(HttpServer& s);
HttpResponse *httpOpenRequest(NetAddr a, HttpResFunc cb, bool https = 0);

struct HttpRequest {
	HttpRequest(HttpSocket& c, string& t, string& u, utils::stringmap& hd, uint16_t cd, utils::Buffer& n):
	cli(c),type(t),header(hd),content(n),code(cd),uri(u) {
		ssize_t q = u.find('?'); if(q == string::npos) path=u,query=""; else path=u.substr(0,q),query=u.substr(q+1);
	}
	HttpSocket& cli; string type,uri,path,query; utils::stringmap header; utils::Buffer content; uint16_t code;
};

class HttpSocket {
	void *ssl=0; utils::Buffer *cBuf=0; size_t cOfs;
	bool chk; HttpRequest *req; HttpResponse *eRes;
	public: HttpServer *srv; Socket cli; const string& name;
	HttpSocket(HttpServer& s, Socket c); HttpSocket(Socket c);
	void init(); bool initCli(bool https, HttpResFunc& cb);
	inline void cclose(); inline ssize_t write(utils::Buffer b);
	private: uint8_t run(char *b); uint8_t parse(utils::Buffer b);
	bool bCopy(const char *buf, size_t len, size_t *rs = 0);
	uint8_t parseChunk(const char *buf, size_t len);
	inline ssize_t read(char *buf, size_t len);
	void sendCode(uint16_t code, string msg);
};

class HttpResponse {
	bool keepAlive,useChunked=0,ended=0; uint8_t gzip=0; uint16_t stat=0;
	const char *cm; utils::stringmap *hdr; string sMsg=""; utils::Buffer *cont;
	public: HttpSocket& cli; HttpResponse(HttpSocket& c, bool k); HttpResponse(HttpSocket& c);
	inline void setGzip(uint8_t gz) { if(!stat) gzip=gz; }
	inline void setUseChunked(bool uc) { if(!stat) useChunked=uc; }
	inline void setKeepAlive(bool ka) { if(!stat) keepAlive=ka; }
	inline uint16_t getStat() { return stat; }
	inline string& getStatMsg() { return sMsg; }
	inline utils::stringmap *getHeaders() { return hdr; }
	inline bool isEnded() { return ended; }
	bool sendCode(uint16_t code, string msg, string desc = "");
	inline bool writeHead(uint16_t code, utils::stringmap *headers = 0) { return writeHead(code,"",headers); }
	bool writeHead(uint16_t code, string status, utils::stringmap *headers = 0);
	bool writeHead(const char *path = 0, const char *method = 0, utils::stringmap *headers = 0);
	bool write(utils::Buffer data); bool end();
	private: utils::Buffer genHeader();
};

}