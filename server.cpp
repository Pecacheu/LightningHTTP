//LightningHTTP Server ©2021 Pecacheu; GNU GPL 3.0
#include "server.h"

//#include <sys/inotify.h>
#include <experimental/filesystem>
#include <fstream>
//#include <sys/stat.h>
//#include <unistd.h>
#include <openssl/md5.h>
#include <zlib.h>

using namespace utils;
namespace fs = experimental::filesystem;
using namespace placeholders; //For std::bind

/*#define FS_ACCESS IN_ACCESS
#define FS_ATTRIB IN_ATTRIB
#define FS_CLOSE_WRITE IN_CLOSE_WRITE
#define FS_CLOSE_NOWRITE IN_CLOSE_NOWRITE
#define FS_CREATE IN_CREATE
#define FS_DELETE IN_DELETE
#define FS_DELETE_SELF IN_DELETE_SELF
#define FS_MODIFY IN_MODIFY
#define FS_MOVE_SELF IN_MOVE_SELF
#define FS_MOVED_FROM IN_MOVED_FROM
#define FS_MOVED_TO IN_MOVED_TO
#define FS_OPEN IN_OPEN
#define FS_ISDIR IN_ISDIR*/

/*struct FSEvent {
	FSEvent(string n, uint32_t m, uint32_t e):name(n),mask(m),eid(e) {}
	uint32_t mask,eid; string name;
};

typedef void(*FWFunc)(FSEvent);

int fileInitWatcher(FWFunc onEvent); void fileStopWatcher();
int fileWatch(string path, bool rc = 0);
bool fileUnwatch(int wd);

string fileExt(string& f);

bool fileExists(string& p);
int writeFile(string& p, utils::Buffer& b);
utils::Buffer readFile(string& p);


typedef unordered_map<int,string&> FWSData;
struct FWData {
	FWData(int w, string p, FWSData *sp):wd(w),path(p),sp(sp) {}
	void close(); int wd; string path; FWSData *sp;
};

int FileInf=0; volatile bool FWr=0;
FWFunc FSOnEvent; unordered_map<int,FWData> FWPaths;

void FWData::close() {
	//cout << "UNWATCH " << path << '\n';
	inotify_rm_watch(FileInf,wd); if(!sp) return;
	for(auto& w: *sp) {
		//cout << "UNWATCH SUB " << w.second << '\n';
		inotify_rm_watch(FileInf,w.first); FWPaths.erase(w.first);
	}
	delete sp;
}

void fileStopWatcher() { FWr=0; if(FileInf) close(FileInf); FileInf=0; }
int fileInitWatcher(FWFunc onEvent) {
	if(!onEvent) return -1; FSOnEvent = onEvent;
	if((FileInf = inotify_init()) < 0) return -2;
	return 0;
}
int subFileWatch(int wp, string& p) {
	int w = inotify_add_watch(FileInf,p.c_str(),IN_ALL_EVENTS); if(w < 0) return w;
	FWPaths.emplace(w,FWData(wp,p,0)); return w;
}
void fwThread() {
	char b[4096] __attribute__ ((aligned(__alignof__(inotify_event))));
	ssize_t len; size_t es=sizeof(inotify_event); inotify_event *e;
	while(FWr) {
		e=0; len = read(FileInf,b,4096); if(ckErr(len,"fileWatchRread")) break;
		for(char *p=b,*l=b+len; p<l; p += es+(e?e->len:0)) {
			e = (inotify_event*)p; FWData *sd,*fd; try { sd = &FWPaths.at(e->wd); } catch(out_of_range e) { continue; }
			try { fd=sd->wd==e->wd?sd:&FWPaths.at(sd->wd); } catch(out_of_range e) { cout << "FW UNKNOWN ERROR "+sd->path+"\n"; continue; }
			uint32_t& m=e->mask; string n=e->len?e->name:"", fp=sd->path+"/"+n;
			if(fd->sp && m & FS_ISDIR && n.size() && n != sd->path) {
				bool sf=0; int sk=0; for(auto& w: *fd->sp) if(w.second == fp) { sf=1,sk=w.first; break; }
				if(!sf && m & (FS_MODIFY | FS_CREATE | FS_MOVED_TO)) {
					//cout << "WATCH RT SUB " << fp << '\n';
					int w=subFileWatch(fd->wd,fp); if(w >= 0) {
						fd->sp->emplace(w,FWPaths.at(w).path);
						for(auto& p: fs::recursive_directory_iterator(fp)) if(fs::is_directory(p.status())) {
							string s = p.path().generic_string();
							//cout << "WATCH RT R-SUB " << s << '\n';
							w = subFileWatch(fd->wd,s);
							if(w >= 0) fd->sp->emplace(w,FWPaths.at(w).path);
						}
					}
				} else if(sf && m & (FS_DELETE | FS_MOVED_FROM)) {
					//cout << "UNWATCH RT SUB " << fp << '\n';
					inotify_rm_watch(FileInf,sk); FWPaths.erase(sk); fd->sp->erase(sk);
					vector<int> rem;
					for(auto& w: *fd->sp) if(startsWith(w.second,fp.data())) {
						//cout << "UNWATCH RT R-SUB " << w.second << '\n';
						rem.push_back(w.first);
					}
					for(int& w: rem) { inotify_rm_watch(FileInf,w); FWPaths.erase(w); fd->sp->erase(w); }
				}
			}
			FSOnEvent(FSEvent(fp,m,e->cookie));
		}
	}
	FWr=0;
}
int fileWatch(string path, bool rc) {
	int w = inotify_add_watch(FileInf,path.c_str(),IN_ALL_EVENTS); if(w < 0) return w;
	//cout << "WATCH " << path << '\n';
	FWSData *sp=0; if(rc) {
		int wd; size_t ps=path.size()+1; sp=new FWSData();
		for(auto& p: fs::recursive_directory_iterator(path)) if(fs::is_directory(p.status())) {
			string s = p.path().generic_string(); wd = subFileWatch(w,s);
			if(wd < 0) { FWData(w,path,sp).close(); return wd; }
			//cout << "WATCH SUB " << s << '\n';
			sp->emplace(wd,FWPaths.at(wd).path);
		}
	}
	if(!FWr) { FWr=1; thread(fwThread).detach(); }
	FWPaths.emplace(w,FWData(w,path,sp)); return w;
}
bool fileUnwatch(int wd) {
	auto fd = FWPaths.find(wd); if(fd == FWPaths.end() || fd->second.wd != wd) return 0;
	fd->second.close(); FWPaths.erase(wd); return 1;
}*/

//--------------------------------------------------------------------------------------------------
//------------------------------------- Filesystem Help --------------------------------------------
//--------------------------------------------------------------------------------------------------

string fileExt(string& f) {
	size_t p = f.rfind('.'); if(p == string::npos) return "";
	return f.find('/',p+1)==string::npos?f.substr(p+1):"";
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
	if(!f.is_open()) return Buffer(string::npos);
	size_t l = f.tellg(); char *d=new char[l];
	f.seekg(0); f.read(d,l); f.close();
	return Buffer(d,l);
}

//--------------------------------------------------------------------------------------------------
//----------------------------------------- Server -------------------------------------------------
//--------------------------------------------------------------------------------------------------

namespace server {

WebServer::WebServer(string d, size_t m, ServerOpt& o)
:Root(d),RootLen(d.size()),CacheMax(m),o(o) {}
void WebServer::stop(int e) { SEr=e; evl.stop(); }

int WebServer::init(string n, uint16_t port, uint16_t sPort, SSLList *sl) {
	if(sPort && !sl) return -1;
	if(!fs::is_directory(Root)) { error("Dir "+Root+ " Not Found"); return -2; }
	//Start servers:
	HttpOptions opt; opt.onRequest=bind(&WebServer::onReq,this,_1,_2); opt.preRequest=o.preReq;
	if(port) { sr=httpStartServer(port,n,opt); if(!sr) { error("Start "+n,-1); return -3; }}
	if(sPort) { ss=httpStartServer(sPort,n+":s",opt,sl); if(!ss) { error("Start "+n+":s",-1); return -4; }}
	//Start FileWatcher:
	cacheAddDir("",1); cout << "File Cache: " << (CacheSize/1000.f) << "KB\n";
	//if(ckErr(fileInitWatcher(onFileChanged),"fwInit") || ckErr(fileWatch(Root,1),"fileWatch")) return -5;
	//Run EventLoop:
	evl.run(); cout << "Stopping "+n+" Server...\n";
	sr->stop(); ss->stop(); //fileStopWatcher();
	this_thread::sleep_for(50ms); return SEr;
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
			if(mh != req.header.end() && mh->second == *c.hash) {
				setHd; res.writeHead(304,&hd); res.end();
				CRUnlk(req); endRq;
			}
			hd["ETag"] = *c.hash;
		}
		if(c.type) hd["Content-Type"] = *c.type;
		size_t ofs=0; bool mr=0; auto rh=req.header.find("Range");
		if(!c.zip && rh != req.header.end()) {
			string& r=rh->second,s;
			if(!startsWith(r,"bytes=")) ofs=string::npos; else {
				size_t n=r.find('-',7); if(n == string::npos) ofs=n;
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

CacheEntry *WebServer::resolve(string& uri) {
	size_t l=uri.size(); auto fe=FileCache.end();
	if(l == 1 && uri[l-1] == '/') uri = "/index.html"; else if(l <= 1) return 0;
	auto fi=FileCache.find(uri); if(fi!=fe) return &fi->second;
	if(uri.find('.',2) == string::npos) {
		fi=FileCache.find(uri+".html"); if(fi!=fe) return &fi->second;
		fi=FileCache.find(uri+"/index.html"); if(fi!=fe) return &fi->second;
	}
	return 0;
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

//Read Files:

void WebServer::cacheAddDir(string path, bool fr) {
	CWLock();
	if(fr) for(auto& p: fs::recursive_directory_iterator(Root+path)) if(fs::is_regular_file(p.status())) {
		string f=p.path().generic_string(); if(f[RootLen+1] == '+') cacheInsert(f,1); //Headers first
	}
	for(auto& p: fs::recursive_directory_iterator(Root+path))
		if(fs::is_regular_file(p.status())) cacheInsert(p.path().generic_string(),fr);
	CWUnlk();
}

//TODO: Full URL Encode instead of replaceAll
void WebServer::cacheInsert(string f, bool fr) {
	//Create new CacheEntry if none exists:
	string n=f.substr(RootLen); replaceAll(n," ","%20"); auto fi=FileCache.emplace(n,CacheEntry());
	auto& e=*fi.first; CacheEntry& c=e.second; if(fi.second) c.setName((string*)&e.first);
	//Read file:
	bool z = !c.type || !(c.type == tWoff || c.type == tWoff2 || c.type == tWoff2
		|| c.type == tJpg || startsWith(*c.type,"video") || startsWith(*c.type,"audio"));
	Buffer b; if(o.readCustom) b=o.readCustom(f,c,&z); if(!b.len && b.len != string::npos) b=readFile(f);
	if(b.len == string::npos) { if(fr) return stop(-11); else b.len=0; }
	CacheSize = c.update(*this,b,CacheSize,z);
	cout << "\033[90m" << (fi.second?"CADD ":"CUPD ") << n << " " <<
		(c.hash?*c.hash:"0") << " " << (c.data?c.fs:0) << "B\033[0m\n";
}

/*void cacheDelete(string n) {
	auto fi = FileCache.find(n); if(fi == FileCache.end()) return;
	CacheEntry& c = fi->second; if(c.data) { CacheSize -= c.fs; delete[] c.data; }
	cout << "\033[90mCREM "+*c.name+"\033[0m\n"; FileCache.erase(fi);
}

inline void cacheRemDir(string& p) {
	cacheLock(); vector<string*> rem;
	for(auto& f: FileCache) if(startsWith(f.first,p.data())) rem.push_back((string*)&f.first);
	for(auto& f: rem) cacheDelete(*f); cacheUnlock();
}

struct FRData {
	FRData(string n, bool i):n(n),in(i) {} string n; bool in=0;
};
unordered_map<string,size_t> FRTimers;

void fileRehash(void *p) {
	FRData *d=(FRData*)p; FRTimers[d->n] = 0;
	cacheLock(); if(d->in) cacheInsert(Root+d->n,0); else cacheDelete(d->n); cacheUnlock();
	delete d; cout << "File Cache: " << (CacheSize/1000.f) << "KB\n";
}

void onFileChanged(FSEvent e) {
	uint32_t& m = e.mask; bool in,dir=m&FS_ISDIR; string n = e.name.substr(RootLen);
	if(m & (FS_MODIFY | FS_CLOSE_WRITE | FS_CREATE | FS_MOVED_TO)) in=1;
	else if(m & (FS_DELETE | FS_MOVED_FROM)) in=0; else return;
	if(dir) {
		if(in) cacheAddDir(n,0); else cacheRemDir(n);
		cout << "File Cache: " << (CacheSize/1000.f) << "KB\n";
	} else {
		FRData *d = new FRData(n,in); size_t& t = FRTimers[n];
		if(t) evl.clearTimeout(t); t = evl.setTimeout(fileRehash,300,d);
	}
}*/

//--------------------------------------------------------------------------------------------------
//----------------------------------------- Cache Update -------------------------------------------
//--------------------------------------------------------------------------------------------------

string *md5hash(Buffer& b) {
	char d[MD5_DIGEST_LENGTH]; MD5((uint8_t*)b.buf,b.len,(uint8_t*)&d);
	char c[(MD5_DIGEST_LENGTH*4/3)+4]; Buffer((char*)&d,MD5_DIGEST_LENGTH).toBase64((char*)&c+1);
	size_t l=strlen((char*)&c+1); c[0]=c[l+1]='"'; return new string((char*)&c,l+2);
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
			auto fi=s.FileCache.find("/"+hn+".html"); if(fi != s.FileCache.end()) {
				CacheEntry& h=fi->second; n++; size_t bl=b.len-n, nl=h.fs+bl; char *nb=new char[nl];
				memcpy(nb,h.data,h.fs); memcpy(nb+h.fs,b.buf+n,bl); delete &b; b=Buffer(nb,nl);
			} else { z=0,b=Append::buf("File Error '",hn,"'"); }
		}
	}
	zip=z?1:0; //1 = Gzip Header, 2 = Zlib Header
	if(z) { //Compress:
		cout << "\033[33m--> ZLIB " << *name;
		Buffer bo=b; b=zlibCompress(b,zip==1); float cr=b.len/(float)bo.len;
		if(cr > 0.95) { delete &b; b=bo,zip=0; } else delete &bo;
		cout << (zip?"":"\033[31m") << " RATIO " << cr << "\033[0m\n";
	}
	//Update Data:
	size_t ncs=cs+(fs=b.len); bool c = fs && ncs < s.CacheMax;
	delete[] hash; if(c) data=b.buf,db=b.db,hash=md5hash(b); else data=0,db=0,hash=0;
	if(ncs >= s.CacheMax) cout << "\033[31mCache size exceeded!\033[0m\n";
	return c?ncs:cs;
}

CacheEntry::~CacheEntry() { delete hash; delete[] db; }

}