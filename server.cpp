//LightningHTTP ©2021 Pecacheu; GNU GPL 3.0

#include "server.h"
#include <unordered_set>
#include <experimental/filesystem>
#include <fstream>
#include <sys/inotify.h>
#include <openssl/md5.h>
#include <zlib.h>

using namespace utils;
namespace fs = experimental::filesystem;
using namespace placeholders; //For std::bind

namespace server {

//--------------------------------------------------------------------------------------------------
//--------------------------------------- File Watcher ---------------------------------------------
//--------------------------------------------------------------------------------------------------

struct FSEvent {
	FSEvent(string n, uint32_t m, uint32_t e):name(n),mask(m),eid(e) {}
	uint32_t mask,eid; string name;
};
class FileWatcher; struct FWData {
	FWData(int w, string& n, bool r):wd(w),path(n),rc(r) {}
	void del(FileWatcher *f); void delAll(FileWatcher *f);
	int wd; string path; bool rc;
};
typedef function<void(FSEvent)> FWFunc;
class FileWatcher {
	public: int init(FWFunc f); void stop();
	int watch(string fp, bool rc); bool unwatch(int w);
	int np; unordered_map<int,FWData> Paths;
	private: FWData *fWatch(string& p, bool r);
	FWData *getPath(string n); void fwThread();
	FWFunc EV; volatile bool Run=0;
	recursive_mutex fl;
};

int FileWatcher::init(FWFunc f) { if(Run) return -1; EV=f; return np=inotify_init(); }
void FileWatcher::stop() { Run=0; fl.lock(); if(np) close(np); np=0; fl.unlock(); }

int FileWatcher::watch(string fp, bool rc) {
	fl.lock(); for(auto& p: Paths) if(fp == p.second.path) { fl.unlock(); return 0; }
	cout << "WATCH " << fp << '\n';
	FWData *ws,*w=fWatch(fp,rc); if(!w) { fl.unlock(); return -1; }
	for(auto& p: fs::recursive_directory_iterator(fp)) if(fs::is_directory(p.status())) {
		string s=p.path().generic_string(); ws=fWatch(s,rc); if(!ws) { w->del(this); fl.unlock(); return -2; }
		cout << "WATCH SUB " << s << '\n';
	}
	if(!Run) { Run=1; thread(bind(&FileWatcher::fwThread,this)).detach(); }
	fl.unlock(); return 0;
}
FWData *FileWatcher::fWatch(string& n, bool r) {
	int w=inotify_add_watch(np,n.c_str(),IN_ALL_EVENTS); if(w<0) return 0;
	return &Paths.emplace(w,FWData(w,n,r)).first->second;
}
FWData *FileWatcher::getPath(string n) {
	for(auto& p: Paths) if(n == p.second.path) return &p.second;
	return 0;
}
bool FileWatcher::unwatch(int w) {
	fl.lock(); auto it=Paths.find(w); if(it == Paths.end()) { fl.unlock(); return 0; }
	it->second.delAll(this); fl.unlock(); return 1;
}
void FWData::delAll(FileWatcher *f) {
	cout << "UNWATCH " << path << '\n'; vector<FWData*> rm;
	for(auto& p: f->Paths) if(startsWith(p.second.path,path)) rm.push_back(&p.second);
	for(auto& w: rm) w->del(f);
}
inline void FWData::del(FileWatcher *f) {
	cout << "UNWATCH SUB " << path << '\n';
	inotify_rm_watch(f->np,wd); f->Paths.erase(wd);
}

void FileWatcher::fwThread() {
	char b[4096] __attribute__ ((aligned(__alignof__(inotify_event))));
	ssize_t len; FWData *fd; size_t es=sizeof(inotify_event); inotify_event *e;
	while(Run) {
		len=read(np,b,4096); if(ckErr(len,"fwRead")) break; fl.lock();
		for(char *p=b,*l=b+len; p<l; p += es+(e?e->len:0)) {
			e=(inotify_event*)p; uint32_t& m=e->mask; string n=e->len?e->name:"";
			try { fd=&Paths.at(e->wd); } catch(out_of_range r) { continue; }
			string fp=fd->path+"/"+n; if(m&IN_ISDIR && e->len) { //Add/rem sub-dirs:
				if(fd->rc && m & (IN_MODIFY | IN_CREATE | IN_MOVED_TO)) {
					cout << "WATCH RT SUB " << (m==IN_MODIFY?"MOD":(m==IN_CREATE?"CREATE":"MOVED_TO")) << " " << fp << '\n';
					if(ckErr(watch(fp,1),"fwWatchSub")) continue;
				} else if(m & (IN_DELETE | IN_MOVED_FROM)) {
					cout << "UNWATCH RT SUB " << (m==IN_DELETE?"DEL":"MOVED_FROM") << " " << fp << '\n';
					if(!(fd=getPath(fp))) { error("fwUnWatch "+fp); continue; }
					fd->delAll(this);
				}
			}
			EV(FSEvent(fp,m,e->cookie));
		}
		fl.unlock();
	}
	Run=0;
}

//--------------------------------------------------------------------------------------------------
//------------------------------------- Filesystem Help --------------------------------------------
//--------------------------------------------------------------------------------------------------

string fileExt(string& f) {
	size_t p = f.rfind('.'); if(p == NPOS) return "";
	return f.find('/',p+1)==NPOS?f.substr(p+1):"";
}

/*bool fileExists(string& p) {
	struct stat s; return stat(p.c_str(), &s) == 0;
}

int writeFile(string& p, Buffer& b) {
	ofstream f(p, ios::binary); if(!f.is_open()) return -1;
	f.write(b.buf,b.len); ios_base::iostate e = f.rdstate();
	f.close(); return e==ios::failbit?-2:(e?-3:0);
}*/

Buffer readFile(string& p) {
	ifstream f(p, ios::binary|ios::ate);
	if(!f.is_open()) return Buffer(NPOS);
	size_t l = f.tellg(); char *d=new char[l];
	f.seekg(0); f.read(d,l); f.close();
	return Buffer(d,l);
}

//--------------------------------------------------------------------------------------------------
//----------------------------------------- Server -------------------------------------------------
//--------------------------------------------------------------------------------------------------

WebServer::WebServer(string d, size_t cm, ServerOpt& o):Root(d),RootLen(d.size()),CacheMax(cm),o(o) {}
void WebServer::stop(int e) { SEr=e||999; evl.stop(); }

int WebServer::init(string n, uint16_t port, uint16_t sPort, SSLList *sl) {
	if((!port && !sPort) || (sPort && !sl)) return -1;
	if(!fs::is_directory(Root)) { error("Dir "+Root+ " Not Found"); return -2; }
	//Start servers:
	HttpOptions opt; opt.onRequest=bind(&WebServer::onReq,this,_1,_2); opt.preRequest=o.preReq;
	if(port) { sr=httpStartServer(port,n,opt); if(!sr) { error("Start "+n,-3); return -3; }}
	if(sPort) { ss=httpStartServer(sPort,n+":s",opt,sl); if(!ss) { error("Start "+n+":s",-4); return -4; }}
	//Start FileWatcher:
	cacheAddDir("",1); cout << "File Cache: " << (CacheSize/1000.f) << "KB\n";
	FileWatcher fw; if(ckErr(fw.init(bind(&WebServer::onFileChg,this,_1)),"fwInit")) return -5;
	if(ckErr(fw.watch(Root,1),"fWatch")) return -6;
	//Run EventLoop:
	if(!SEr) evl.run(); cout << "Stopping "+n+" Server...\n";
	fw.stop(); if(sr) sr->stop(); if(ss) ss->stop();
	this_thread::sleep_for(50ms); return SEr==999?0:SEr;
}

#define setHd if(o.setHdr) o.setHdr(req,res,hd)
#define endRq if(o.postReq) o.postReq(req,res); return
void WebServer::onReq(HttpRequest& req, HttpResponse& res) {
	//Handle special:
	if(o.onReq) { o.onReq(req,res); if(res.isEnded()) { endRq; }}
	if(req.path.size() > 1 && req.path[1] == '+') {
		res.sendCode(404,"Not Found"); endRq;
	}
	//Check cache for file:
	CRLock(req); CacheEntry *cp = req.type=="GET"?resolve(req.path):0;
	if(!cp) { res.sendCode(404,"Not Found"); CRUnlk(req); endRq; }
	//Send from CacheEntry:
	stringmap hd; CacheEntry& c=*cp;
	if(c.data) {
		if(c.hash) {
			auto mh = req.header.find("If-None-Match");
			if(mh != req.header.end() && mh->second == c.hash) {
				setHd; res.writeHead(304,&hd); res.end();
				CRUnlk(req); endRq;
			}
			hd["ETag"] = c.hash;
		}
		if(c.type) hd["Content-Type"] = *c.type;
		size_t ofs=0; bool mr=0; auto rh=req.header.find("Range");
		if(!c.zip && rh != req.header.end()) {
			string& r=rh->second,s;
			if(!startsWith(r,"bytes=")) ofs=NPOS; else {
				size_t n=r.find('-',7); if(n == NPOS) ofs=n;
				else s=r.substr(6,n-6), ofs=strToUint(s);
			}
			if(ofs >= c.fs) { res.sendCode(416,"Invalid Range"); CRUnlk(req); endRq; }
			mr=1; hd["Content-Range"] = "bytes "+s+"-"+to_string(c.fs-1)+"/"+to_string(c.fs);
			cout << ">>>> BYTE OFS "+s+"\n";
		}
		if(c.zip) res.setGzip(c.zip); res.setUseChunked(1); setHd;
		res.writeHead(mr?206:200,&hd); res.write(Buffer(c.data+ofs,c.fs-ofs)); res.end();
	} else res.sendCode(404, "Not Found", "Error: File Known but Not Cached");
	CRUnlk(req); endRq;
}

//--------------------------------------------------------------------------------------------------
//------------------------------------- Smart Cache System -----------------------------------------
//--------------------------------------------------------------------------------------------------

stringmap ContentTypes({
	{"html",	"text/html"},
	{"php",		"text/html"},
	{"css",		"text/css"},
	{"png",		"image/png"},
	{"jpg",		"image/jpeg"},
	{"svg",		"image/svg+xml"},
	{"js",		"application/javascript"},
	{"pdf",		"application/pdf"},
	{"mp3",		"audio/mpeg"},
	{"mp4",		"video/mp4"},
	{"ogg",		"video/ogg"},
	{"webm",	"video/webm"},
	{"otf",		"application/opentype"},
	{"ttf",		"application/truetype"},
	{"woff",	"application/font-woff"},
	{"woff2",	"application/font-woff2"}
});

const string *tHtml=&ContentTypes["html"], *tJs=&ContentTypes["js"], *tCSS=&ContentTypes["css"],
*tWoff=&ContentTypes["woff"], *tWoff2=&ContentTypes["woff2"], *tJpg=&ContentTypes["jpg"];

auto CTEnd=ContentTypes.end();
void CacheEntry::setName(string *n) {
	auto i=ContentTypes.find(fileExt(*n));
	name=n,type=(i==CTEnd?0:(string*)&i->second);
}

CacheEntry *WebServer::resolve(string& u) {
	size_t l=u.size(); if(!l || u[0] != '/') return 0;
	if(l==1) return getFile("/index.html");
	u=decodeURIComponent(u);
	CacheEntry *c=getFile(u); if(c) return c;
	if(u.find('.',2) == NPOS) {
		c=getFile(u+".html"); if(c) return c;
		c=getFile(u+"/index.html"); if(c) return c;
	}
	return 0;
}
CacheEntry *WebServer::getFile(string n) {
	auto fi=FileCache.find(n); if(fi == FileCache.end()) return 0;
	return &fi->second;
}

void WebServer::CRLock(HttpRequest& r) {
	CW.lock(); CR.lock(); ReadCache.push_back(&r.cli); CR.unlock(); CW.unlock();
}
void WebServer::CRUnlk(HttpRequest& r) {
	CR.lock(); for(auto i=ReadCache.begin(),e=ReadCache.end(); i!=e; i++)
		if(*i == &r.cli) { ReadCache.erase(i); break; } CR.unlock();
}

void WebServer::CWLock() {
	CW.lock(); CR.lock(); size_t n=ReadCache.size(); CR.unlock();
	if(n) {
		cout << to_string(n)+"T waiting for update 200ms...\n";
		this_thread::sleep_for(200ms); //If open clients, wait for grace period.
		CR.lock(); for(auto& i: ReadCache) (*i).cli.close(); CR.unlock();
		this_thread::yield(); //Wait for client threads to exit.
	}
}
inline void WebServer::CWUnlk() { CW.unlock(); }

//Detect Changes:

struct FRData {
	FRData(string n, bool c):n(n),cr(c) {} string n; bool cr;
};

void WebServer::onFileChg(FSEvent e) {
	uint32_t& m=e.mask; bool cr,dir=m&IN_ISDIR; string n=e.name.substr(RootLen);
	if(m & (IN_MODIFY | IN_CLOSE_WRITE | IN_CREATE | IN_MOVED_TO)) cr=1;
	else if(m & (IN_DELETE | IN_MOVED_FROM)) cr=0; else return;
	if(dir) {
		if(cr) cacheAddDir(n); else cacheRemDir(n);
		cout << "File Cache: " << (CacheSize/1000.f) << "KB\n";
	} else {
		FRData *d=new FRData(n,cr); size_t& t=FRTimers[n]; if(t) evl.clearTimeout(t);
		t=evl.setTimeout(bind(&WebServer::fileRecalc,this,_1),300,d);
	}
}

void WebServer::fileRecalc(void *p) {
	FRData *d=(FRData*)p; FRTimers[d->n]=0;
	CWLock(); if(d->cr) cacheInsert(Root+d->n,0); else cacheDelete(d->n); CWUnlk();
	delete d; cout << "File Cache: " << (CacheSize/1000.f) << "KB\n";
}

//Add/Delete Files:

void WebServer::cacheAddDir(string path, bool fr) {
	CWLock();
	if(fr) for(auto& p: fs::recursive_directory_iterator(Root+path)) if(fs::is_regular_file(p.status())) {
		string f=p.path().generic_string(); if(f[RootLen+1] == '+') cacheInsert(f,1); //Headers first
	}
	for(auto& p: fs::recursive_directory_iterator(Root+path))
		if(fs::is_regular_file(p.status())) { cacheInsert(p.path().generic_string(),fr); if(SEr) return; }
	CWUnlk();
}
void WebServer::cacheInsert(string f, bool fr) {
	//Create new CacheEntry if none exists:
	string n=f.substr(RootLen); auto fi=FileCache.emplace(n,CacheEntry());
	auto& e=*fi.first; CacheEntry& c=e.second; if(fi.second) c.setName((string*)&e.first);
	//Read file:
	bool z = !c.type || !(c.type == tWoff || c.type == tWoff2 || c.type == tWoff2
		|| c.type == tJpg || startsWith(*c.type,"video") || startsWith(*c.type,"audio"));
	Buffer b; if(o.readCustom) b=o.readCustom(f,c,&z); if(!b.len && b.len != NPOS) b=readFile(f);
	if(b.len == NPOS) { if(fr) return stop(-11); else b.len=0; }
	CacheSize = c.update(*this,b,CacheSize,z);
	cout << "\033[90m" << (fi.second?"CADD ":"CUPD ") << n << " " <<
		(c.hash?c.hash:"0") << " " << (c.data?c.fs:0) << "B\033[0m\n";
}

void WebServer::cacheRemDir(string& p) {
	CWLock(); vector<string*> rm;
	for(auto& f: FileCache) if(startsWith(f.first,p)) rm.push_back((string*)&f.first);
	for(auto& f: rm) cacheDelete(*f); CWUnlk();
}
void WebServer::cacheDelete(string n) {
	auto fi=FileCache.find(n); if(fi == FileCache.end()) return;
	cout << "\033[90mCREM "+fi->first+"\033[0m\n";
	FileCache.erase(fi);
}

//--------------------------------------------------------------------------------------------------
//----------------------------------------- Cache Update -------------------------------------------
//--------------------------------------------------------------------------------------------------

const char *md5hash(Buffer& b) {
	char d[MD5_DIGEST_LENGTH]; MD5((uint8_t*)b.buf,b.len,(uint8_t*)&d);
	char *c=new char[(MD5_DIGEST_LENGTH*4/3)+4]; Buffer((char*)&d,MD5_DIGEST_LENGTH).toBase64(c+1);
	size_t l=strlen(c+1); c[0]=c[l+1]='"'; c[l+2]=0; return c;
}

Buffer zlibCompress(Buffer d, bool gzip) {
	z_stream str; str.zalloc=0; str.zfree=0; str.opaque=0;
	if(ckErr(deflateInit2(&str, 9, Z_DEFLATED, gzip?31:15, 9, Z_DEFAULT_STRATEGY),"zLib deflateInit2")) return Buffer();
	str.next_in = (uint8_t*)d.buf; str.avail_in = d.len; size_t n,s=d.len*0.8,sIn=d.len*0.2;
	uint8_t *o,*b=new uint8_t[s]; int r; str.next_out=b; str.avail_out=s;
	while(1) {
		if((r=deflate(&str, Z_FINISH)) == Z_STREAM_ERROR) { error("zLib deflate"); deflateEnd(&str); return Buffer(); }
		if(r == Z_STREAM_END) { deflateEnd(&str); return Buffer((char*)b,s-str.avail_out); }
		if(!str.avail_out) {
			o=b; n=s+sIn, b=new uint8_t[n]; memcpy(b,o,s);
			delete[] o; str.next_out=b+s; str.avail_out=sIn; s=n;
		}
	}
}

size_t CacheEntry::update(WebServer& s, Buffer b, size_t cs, bool z) {
	if(data) { delete[] db; cs-=fs; } if(b.len<100) z=0;
	if(endsWith(*name,".html")) { //Check for header:
		if((*name)[1] == '+') z=0; else if(b.len > 20 && b[0] == '+') {
			size_t n=1; while(*(b.buf+n) != '+') if(++n == 20) break; string hn=string(b.buf,n);
			CacheEntry *h=s.getFile("/"+hn+".html"); if(h) {
				n++; size_t bl=b.len-n, nl=h->fs+bl; char *nb=new char[nl];
				memcpy(nb,h->data,h->fs); memcpy(nb+h->fs,b.buf+n,bl); b.del(); b=Buffer(nb,nl);
			} else { z=0,b=Append::buf("File Error '",hn,"'"); }
		}
	}
	zip=z?1:0; //1 = Gzip Header, 2 = Zlib Header
	if(z) { //Compress:
		cout << "\033[33m--> ZLIB " << *name;
		Buffer bo=b; b=zlibCompress(b,zip==1); float cr=b.len/(float)bo.len;
		if(cr > 0.95) { b.del(); b=bo,zip=0; } else bo.del();
		cout << (zip?"":"\033[31m") << " RATIO " << cr << "\033[0m\n";
	}
	//Update Data:
	size_t ncs=cs+(fs=b.len); bool c = fs && ncs < s.CacheMax;
	delete[] hash; if(c) data=b.buf,db=b.db,hash=md5hash(b); else data=0,db=0,hash=0;
	if(ncs >= s.CacheMax) cout << "\033[31mCache size exceeded!\033[0m\n";
	return c?ncs:cs;
}
CacheEntry::~CacheEntry() { delete[] hash; delete[] db; }

}