//LightningHTTP v3.6.1 ©2021 Pecacheu; GNU GPL 3.0
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
	const char *data=0,*db,*hash=0; size_t fs=0;
	string *type,*name; char zip;
};

struct ServerOpt {
	bool chkMode=1; HttpReqFunc onReq=0,postReq=0; HttpPreFunc preReq=0;
	void (*setHdr)(HttpRequest& req, HttpResponse& res, stringmap& hd)=0;
	Buffer (*readCustom)(string f, CacheEntry& c, bool *zip)=0;
};

struct FSEvent;
class WebServer {
	public: WebServer(string d, size_t cm, ServerOpt& o);
	int init(string n, uint16_t port, uint16_t sPort=0, SSLList *sl=0);
	void stop(int e=0); EventLoop evl; const size_t RootLen,CacheMax;
	CacheEntry *getFile(string n);
	private: void onReq(HttpRequest& req, HttpResponse& resp);
	const string Root; HttpServer *sr=0,*ss=0; const ServerOpt o;
	//SmartCache:
	size_t SEr=0,CacheSize=0; vector<HttpSocket*> ReadCache;
	mutex CW,CR; unordered_map<string,CacheEntry> FileCache;
	unordered_map<string,size_t> FRTimers;
	void CRLock(HttpRequest& r); void CRUnlk(HttpRequest& r);
	CacheEntry *resolve(string& u); void CWLock(); void CWUnlk();
	void onFileChg(FSEvent e); void fileRecalc(void *p);
	void cacheAddDir(string path, bool fr=0); void cacheRemDir(string& p);
	void cacheInsert(string path, bool fr); void cacheDelete(string n);
};

}