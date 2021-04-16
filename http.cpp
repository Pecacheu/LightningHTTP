//LightningHTTP ©2021 Pecacheu; GNU GPL 3.0

#include "http.h"
#include <openssl/ssl.h>
#include <sys/utsname.h>
#include <csignal>

namespace http {

string ServerStr = "LightningHTTP/"+string(HTTP_VERSION);
const SSL_METHOD *SrvSSL, *CliSSL; SSL_CTX *CliCTX;
SSL_CTX *createSSLClientContext();

void httpExit() { EVP_cleanup(); }
void httpInit() {
	SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();
	SrvSSL = TLS_server_method(), CliSSL = TLS_method();
	CliCTX = createSSLClientContext();
	utsname os; if(!ckErr(uname(&os),"httpOSCheck {NON FATAL}")) {
		ServerStr += ((string)" (")+
		#ifdef HTTP_SEND_NAME
		os.nodename+", "+
		#endif
		os.sysname+" "+(ARCH64?"x64":os.machine)+")";
	}
	signal(SIGPIPE, SIG_IGN); atexit(httpExit);
}

string httpGetVersion() { return ServerStr; }
static_block { httpInit(); }

int setSrv(SSL *s, int *n, SSLList *sl) {
	const char *h = SSL_get_servername(s, TLSEXT_NAMETYPE_host_name); if(!h) return 0; string hs=h;
	for(size_t i=0; i<sl->len; i++) if(sl->h[i] == hs) { SSL_set_SSL_CTX(s,(SSL_CTX*)sl->s[i]); break; }
	return 0;
}

ssize_t createSSLContext(const char *certFile, const char *keyFile, SSLList *sl) {
	SSL_CTX *ctx = SSL_CTX_new(SrvSSL); if(!ctx) return -1;
	SSL_CTX_set_ecdh_auto(ctx, 1);
	if(SSL_CTX_use_certificate_chain_file(ctx, certFile) != 1) return -2;
	if(SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) != 1) return -3;
	if(SSL_CTX_set_session_id_context(ctx, (uint8_t*)"LightningHTTP", 7) != 1) return -4;
	if(sl) {
		SSL_CTX_set_tlsext_servername_callback(ctx, &setSrv);
		SSL_CTX_set_tlsext_servername_arg(ctx, sl);
	}
	return (ssize_t)ctx;
}

SSL_CTX *createSSLClientContext() {
	SSL_CTX *ctx = SSL_CTX_new(CliSSL); if(!ctx) return 0;
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL); SSL_CTX_set_verify_depth(ctx, 4);
	//SSL_CTX_load_verify_locations(ctx, certFile, NULL);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);
	//BIO *bio = BIO_new_ssl_connect(ctx); BIO_set_conn_hostname(bio, HOST+":https");
	return ctx;
}

int SSLList::add(const char *certFile, const char *keyFile, const char *host) {
	if(i == len) return -6; ssize_t c = createSSLContext(certFile, keyFile, this);
	if(c < 0) return c; s[i] = c; h[i++] = host?host:""; return 0;
}
void SSLList::free() { for(i=0; i<len; i++) SSL_CTX_free((SSL_CTX *)s[i]); delete[] s,h; }

//------------ HttpServer ------------

HttpServer *httpStartServer(uint16_t port, string name, HttpOptions& opt, SSLList *sl) {
	if(sl && sl->len != sl->i) return 0;
	int s = netStartServer(NetAddr(port), HTTP_BACKLOG); if(s < 0) return 0;
	cout << "Started " << name << " server on port " << port << '\n';
	return new HttpServer(s,name,opt,sl);
}

void acceptClient(HttpServer& s) {
	while(s.tx >= HTTP_THREADS) { this_thread::sleep_for(10ms); if(s.st) return; }
	Socket c = netAccept(s.s); if(ckErr(c.err,"netAccept")) return;
	if(ckErr(c.setTimeout(HTTP_TIMEOUT),"setTimeout")) { c.close(); return; }
	HttpSocket *cli = new HttpSocket(s,c); s.tx++;
	thread([cli]() { cli->init(); }).detach();
}

HttpServer::HttpServer(int s, string& n, HttpOptions& o, SSLList *l):s(s),name(n),opt(o),sl(l) {
	thread([this]() { while(!st) acceptClient(*this); }).detach();
}
void HttpServer::stop() { st=1; netClose(s); if(sl) sl->free(); delete this; }

HttpResponse *httpOpenRequest(NetAddr a, HttpResFunc cb, bool https) {
	Socket s = netConnect(a); if(s.err) { cb(s.err,0,0); return 0; }
	HttpSocket *h=new HttpSocket(s); HttpResponse *r=new HttpResponse(*h);
	if(!h->initCli(https,cb)) return 0; return r;
}

//------------ HttpSocket ------------

HttpSocket::HttpSocket(HttpServer& s, Socket c):srv(&s),cli(c),
name(s.name+"->"+c.addr.host+":"+to_string(c.addr.port)+" ("+to_string(c.sck)+")") {}

HttpSocket::HttpSocket(Socket c):srv(0),cli(c),
name(string(c.addr.host)+":"+to_string(c.addr.port)+" ("+to_string(c.sck)+")") {}

void HttpSocket::init() {
	#if HTTP_DEBUG
	cout << name+" Thread 0x" << hex << this_thread::get_id() << dec << '\n';
	#endif
	if(srv->sl) {
		SSL *s = SSL_new((SSL_CTX*)srv->sl->s[0]); SSL_set_fd(s,cli.sck); ssl=s;
		int e=SSL_accept(s); if(e <= 0) {
			#if HTTP_DEBUG
			cout << name+" SSL Error " << SSL_get_error(s,e) << '\n';
			#endif
			cclose(); return;
		}
	}
	char b[HTTP_READ_SIZE]; char r,q=0; bool ka;
	while(!srv->st && (r=run(b)) != 3) {
		if(srv->opt.preRequest && !q) { //Pre-request:
			q=srv->opt.preRequest(*this,req,eRes);
			delete eRes; if(q==2) { delete req; break; }
			if(q==1) r=0; q=1;
		}
		if(!req) break; //Break on header parse error.
		if(r==1 && !eRes) { //Create response:
			if(srv->opt.onRequest) {
				q=0,ka=0; auto kh = req->header.find("Connection");
				if(kh != req->header.end()) ka = kh->second == "keep-alive";
				HttpResponse *res=new HttpResponse(*this,ka);
				srv->opt.onRequest(*req,*res); if(!res->isEnded()) res->end();
				ka=res->kA; delete req; delete res; cBuf.del(); if(!ka) break;
			} else sendCode(204, "No Application");
		}
	}
	cclose(); cBuf.del(); delete this;
}

bool HttpSocket::initCli(bool https, HttpResFunc& cb) {
	HttpResponse *cr=eRes;
	if(https) {
		SSL *s = SSL_new(CliCTX); SSL_set_fd(s,cli.sck); ssl=s;
		SSL_set_tlsext_host_name(s, cli.addr.host);
		X509_VERIFY_PARAM *p = SSL_get0_param(s);
		//X509_VERIFY_PARAM_set_hostflags(p, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
		X509_VERIFY_PARAM_set1_host(p, cli.addr.host, 0);
		if(SSL_connect(s) <= 0) {
			error("SSL "+name,-1); cb(-5,0,0);
			cclose(); delete cr; delete this; return 0;
		}
	}
	thread([this,cb,cr]() {
		char b[HTTP_READ_SIZE]; char r;
		while(!(r=run(b)));
		if(r==1) cb(0,req,0); else if(r==2) {
			uint16_t s=eRes->getStat();
			string m=to_string(s)+" "+eRes->getStatMsg();
			cb(s,0,&m); delete eRes;
		} else cb(-6,0,0);
		cclose(); cBuf.del();
		delete req; delete cr; delete this;
	}).detach(); return 1;
}

char HttpSocket::run(char *b) {
	ssize_t len = read(b, HTTP_READ_SIZE);
	if(len <= 0) {
		#if HTTP_DEBUG
		if(!len || errno == EBADF) cout << name+" Connection Closed\n";
		else if(errno == EAGAIN) cout << name+" Timed Out\n";
		else if(errno == ECONNRESET) cout << name+" Connection Reset\n";
		#else
		if(!len || errno == EAGAIN || errno == ECONNRESET || errno == EBADF) {}
		#endif
		else error(name,len); return 3;
	}
	#if HTTP_DEBUG > 2
	cout << "\n<<IN "+to_string(len)+"b "+name+">>\n"+string(b,len)+"\n<<IN END>>\n";
	#elif HTTP_DEBUG > 1
	cout << name+" IN "+to_string(len)+"\n";
	#endif
	char r = parse(Buffer(b,len));
	#if HTTP_DEBUG
	cout << name+" "+(req?req->type+" "+req->uri:(cBuf.buf?to_string(cBuf.len)+" ":"")+"Read More")+"\n";
	#endif
	return r;
}

char HttpSocket::parse(Buffer r) {
	if(cBuf.buf) { //Read More Data:
		if(chk) return parseChunk(r.buf,r.len);
		char d=bCopy(r.buf,r.len); return d;
	}
	req=0,eRes=0; if(r.len < 23) return 3; //Parse HTTP Headers:
	string t,u,hk,hv; stringmap hd; bool ph=1,nl=0; size_t cl=0,cd=0;
	size_t i,o=0,sl=strlen(HTTP_NEWLINE); const char *rb=r.buf; chk=0;
	while((i=bFind(r,HTTP_NEWLINE,o)) != NPOS) {
		Buffer b=Buffer(rb+o,i-o); o=i+sl;
		if(ph) { //Parse Head:
			ph=0; vector<Buffer> h=bSplit(b," "); size_t hs=h.size();
			if(srv) { //Server Mode:
				if(hs != 3 || !h[2].match("HTTP/1.1")) { sendCode(400, "Invalid Request Head"); return 2; }
				if(h[1].len > 8000) { sendCode(414, "URI Too Long"); return 2; }
				t=h[0].toStr(); u=h[1].toStr(); if(u[0] != '/') { sendCode(400, "Invalid Request URI"); return 2; }
				if(t != "GET" && t != "POST") { sendCode(405, "Unsupported Reqest Type"); return 2; }
			} else { //Client Mode:
				if(hs < 2 || !h[0].matchPart("HTTP/1.") || h[1].len != 3) { sendCode(400, "Invalid Response Head"); return 2; }
				if(hs > 2) t=b.toStr(h[0].len+h[1].len+2); u=h[1].toStr(); cd=strToUint(u); u="";
				if(cd < 100 || cd > 999) { sendCode(400, "Invalid Response Code"); return 2; }
			}
		} else if(!b.len) { //Double-Newline:
			nl=1; break;
		} else { //Parse Header:
			size_t hs=bFind(b,":"); if(hs > 50 || hs < 3) { sendCode(400, "Invalid Header"); return 2; }
			if(b.len-hs < 3) continue; hk=toCamelCase(b.toStr(0,hs)), hv=b.toStr(hs+2);
			if(hk == "Content-Length") {
				cl=strToUint(hv); if(chk || cl == NPOS) { sendCode(400, "Invalid Content-Len"); return 2; }
				if(cl > HTTP_POST_MAX) { sendCode(414, "Content Too Long"); return 2; }
			} else if(hk == "Content-Type" && startsWith(hv,"multipart")) { sendCode(405, "Multipart Unsupported"); return 2; }
			else if(hk == "Transfer-Encoding" && hv == "chunked") { chk=1; cl=0; } else hd[hk] = hv;
		}
	}
	if(!nl) { sendCode(400, "Premature Header End"); return 2; }
	cOfs=0, cBuf=Buffer(cl), req=new HttpRequest(*this,t,u,hd,cd,cBuf);
	if(chk) return parseChunk(r.buf+o,r.len-o);
	if(cl) { char d=bCopy(r.buf+o,r.len-o); return d; }
	cBuf.del(); return 1;
}

char HttpSocket::bCopy(const char *buf, size_t len, size_t *rs) {
	size_t rl=min(cBuf.len-cOfs,len); memcpy((void*)(cBuf.buf+cOfs),buf,rl);
	if(rs) *rs=rl; bool r=(cOfs += rl) == cBuf.len; if(r) cOfs=0; return r?1:0;
}
char HttpSocket::parseChunk(const char *buf, size_t len) {
	if(!len) return 0; size_t rl;
	if(cOfs) { if(!bCopy(buf,len,&rl) || len-rl<=2) return 0; rl+=2; buf+=rl,len-=rl; }
	const char *p=buf; size_t i,cd=min((size_t)8,len); char ck[9];
	for(i=0; (p[i] != ';' && p[i] != '\r'); i++) {
		if(i==cd) { cBuf.del(); sendCode(400, "Invalid Chunk"); return 2; }
		ck[i] = p[i];
	}
	ck[i]=0; string s=ck; cd=hexStrToUint(s); Buffer b=Buffer(buf,len); i=bFind(b,"\n",i);
	if(cd == NPOS || i == NPOS) { cBuf.del(); sendCode(400, "Invalid Chunk-Len"); return 2; }
	if(!cd) return 1; buf+=i+1; len-=i+1; cOfs=cBuf.len;
	if(cOfs+cd > HTTP_POST_MAX) { cBuf.del(); sendCode(414, "Content Too Long"); return 2; }
	b=cBuf; cBuf=Buffer(cOfs+cd); memcpy((void*)cBuf.buf,b.buf,cOfs); b.del();
	return bCopy(buf,len,&rl)&&len-rl>2 ? parseChunk(buf+rl+2,len-rl-2):0;
}

inline void HttpSocket::cclose() {
	if(cli.err) return; cli.err=1; if(srv) srv->tx--; cli.close(); if(ssl) SSL_free((SSL*)ssl);
}
inline ssize_t HttpSocket::read(char *buf, size_t len) {
	if(cli.err) return 0; return ssl?SSL_read((SSL*)ssl,buf,len):cli.read(buf,len);
}
inline ssize_t HttpSocket::write(Buffer b) {
	#if HTTP_DEBUG > 2
	char *cs = (char*)b.toCStr(1);
	for(size_t i=0,l=b.len-3; i<l; i++) if(cs[i] == '\r' && cs[i+1] == '\n'
	&& cs[i+2] == '\r' && cs[i+3] == '\n') { cs[i+2]=cs[i+3]='>'; cs[i+4]=0; break; }
	cout << "\n<<OUT "+to_string(b.len)+"b "+name+">>\n"+cs+"\n<<OUT END>>\n";
	delete[] cs;
	#elif HTTP_DEBUG > 1
	cout << name+" OUT "+to_string(b.len);
	#endif
	ssize_t n = ssl?SSL_write((SSL*)ssl,b.buf,b.len):cli.write(b.buf,b.len);
	#if HTTP_DEBUG > 1
	cout << " WRITE "+to_string(n)+"\n";
	#endif
	b.del(); //Since HttpSocket::write is only called internally, OK to delete.
	return n;
}

void HttpSocket::sendCode(uint16_t code, string msg) {
	string e = "Parser Error: "+to_string(code)+" "+msg;
	#if HTTP_DEBUG
	error(name+" "+e);
	#endif
	eRes=new HttpResponse(*this,0);
	if(srv) eRes->sendCode(code,msg,e); else eRes->writeHead(code,msg);
}

//------------ HttpRequest ------------

HttpRequest::HttpRequest(HttpSocket& c, string& t, string& u, utils::stringmap& hd, uint16_t cd, utils::Buffer& n):
cli(c),type(t),header(hd),content(n),code(cd),uri(u) {
	ssize_t q=u.find('?'); if(q == NPOS) path=u,query=""; else path=u.substr(0,q),query=u.substr(q+1);
}

//------------ HttpResponse ------------

inline Buffer genChunk(Buffer c) { return Append::buf(intToHex(c.len),HTTP_NEWLINE,c,HTTP_NEWLINE); }
HttpResponse::HttpResponse(HttpSocket& c, bool k):cli(c),kA(k),cm(0) {}
HttpResponse::HttpResponse(HttpSocket& c):cli(c),kA(0),cm((char*)1) {}

bool HttpResponse::sendCode(uint16_t code, string msg, string desc) {
	if(stat) return 0; kA=0,uC=0; if(!writeHead(code,msg,0)) return 0; string m = to_string(code)+" "+msg;
	if(!write("<title>"+m+"</title><body style='background:#111;color:#ccc;font:16pt sans-serif;text-align:center'><pre>"
	+m+"</pre>"+(desc.size()?"<p>"+desc+"</p>":"")+"</body>")) return 0;
	return end();
}

bool HttpResponse::writeHead(uint16_t code, string status, stringmap *headers) { //Server Mode
	if(cm || ended || code < 100 || code > 999 || (uC && stat)) return 0;
	if(uC && (code < 200 || code == 204 || code >= 300 && code < 400)) return 0;
	stat=code, sMsg=status, hdr=headers;
	if(uC && cli.write(genHeader()) <= 0) return 0;
	return 1;
}

bool HttpResponse::writeHead(const char *path, const char *method, stringmap *headers) { //Client Mode
	if(!cm || ended || (uC && stat)) return 0;
	stat=1; if(!path) path="/"; if(!method) method="GET";
	cm=Append::str(method,path[0]=='/'?" ":" /",path), hdr=headers;
	if(uC && cli.write(genHeader()) <= 0) return 0;
	return 1;
}

bool HttpResponse::write(Buffer b) {
	if(ended || !b.buf) return 0;
	const char *d=b.db; b.db=0;
	if(uC) { if(!stat || cli.write(genChunk(b)) <= 0) return 0; }
	else cont=Append::buf(cont,b);
	b.db=d; return 1;
}

Buffer HttpResponse::genHeader() {
	stringmap& hd = *(hdr?hdr:new stringmap()); bool cl;
	if(cm) {
		cl=cont.len; auto hf=hd.find("Host");
		if(hf == hd.end()) hd["Host"] = cli.cli.addr.host;
	} else {
		if(stat != 304) hd["Server"] = ServerStr;
		#ifdef HTTP_NO_CORS
		hd["X-Frame-Options"] = "sameorigin";
		#endif
		cl = !(stat < 200 || stat == 204 || stat >= 300 && stat < 400);
	}
	if(gzip) hd["Content-Encoding"] = gzip==2?"deflate":"gzip";
	if(uC) hd["Transfer-Encoding"] = "chunked";
	else if(cl) hd["Content-Length"] = to_string(cont.len); else cont.len=0;
	if(kA) {
		hd["Connection"] = "keep-alive";
		if(!cm) hd["Keep-Alive"] = "timeout="+to_string(HTTP_TIMEOUT);
	}
	string h=""; auto sc=hd.find("Set-Cookie");
	if(sc != hd.end()) {
		Buffer b=sc->second; vector<Buffer> ck=bSplit(b,"&"); hd.erase("Set-Cookie");
		for(Buffer& c: ck) h += "Set-Cookie: "+c.toStr()+HTTP_NEWLINE;
	}
	for(auto& kv: hd) h += kv.first+": "+kv.second+HTTP_NEWLINE; cl=(cm==(void*)1);
	Buffer hb=cm?Append::buf(cl?"GET /":cm," HTTP/1.1",(sMsg.size()?" "+sMsg:""),HTTP_NEWLINE,h,HTTP_NEWLINE,cont):
	Append::buf("HTTP/1.1 ",stat,(sMsg.size()?" "+sMsg:""),HTTP_NEWLINE,h,HTTP_NEWLINE,cont);
	if(cm && !cl) delete[] cm; if(!hdr) delete &hd;
	return hb;
}

bool HttpResponse::end() {
	if(ended) return 0; if(!stat && !cm) writeHead(uC||!cont.len?204:200);
	bool s=cli.write(uC?genChunk(Buffer()):genHeader()) <= 0;
	ended=1; return s;
}

}