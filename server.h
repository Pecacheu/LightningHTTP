//LightningHTTP Server ©2021 Pecacheu; GNU GPL 3.0
#pragma once

#include "http.h"

namespace server {
using namespace http;

extern stringmap ContentTypes;
extern const string *tHtml,*tJs,*tCSS,*tWoff,*tWoff2,*tJpg;

class WebServer;
struct CacheEntry {
	~CacheEntry(); void setName(string *n);
	size_t update(WebServer& s, Buffer b, size_t cs, bool z);
	const char *data=0,*db; size_t fs=0; string *hash=0,*type,*name; char zip;
};

struct ServerOpt {
	HttpReqFunc onReq=0,postReq=0; HttpPreFunc preReq=0;
	void (*setHdr)(HttpRequest& req, HttpResponse& res, stringmap& hd)=0;
	Buffer (*readCustom)(string f, CacheEntry& c, bool *zip)=0;
};

class WebServer {
	public: WebServer(string d, size_t m, ServerOpt& o);
	int init(string n, uint16_t port, uint16_t sPort=0, SSLList *sl=0);
	void stop(int e=0); EventLoop evl; const size_t RootLen,CacheMax;
	unordered_map<string,CacheEntry> FileCache;
	private: void onReq(HttpRequest& req, HttpResponse& resp);
	const string Root; HttpServer *sr,*ss; const ServerOpt o;
	//SmartCache:
	size_t SEr=0,CacheSize=0; vector<HttpSocket*> ReadCache; mutex CW,CR;
	void CRLock(HttpRequest& r); void CRUnlk(HttpRequest& r);
	CacheEntry *resolve(string& uri);
	//File Read:
	void CWLock(); void CWUnlk();
	void cacheAddDir(string path, bool fr=0);
	void cacheInsert(string path, bool fr);
};

}