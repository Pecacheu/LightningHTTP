//LightningHTTP ©2025 Pecacheu; GNU GPL 3.0

#include "http.h"
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <csignal>

#define WS_UUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#if __has_include(<sys/utsname.h>)
	#define HTTP_UTSNAME
	#include <sys/utsname.h>
#endif

namespace http {

string ServerStr = "LightningHTTP/"+string(HTTP_VERSION);
const SSL_METHOD *SrvSSL, *CliSSL; SSL_CTX *CliCTX;
SSL_CTX *createSSLClientContext(bool v);

void httpExit() { EVP_cleanup(); }
void httpInit() {
	SSL_load_error_strings(); OpenSSL_add_ssl_algorithms();
	SrvSSL = TLS_server_method(), CliSSL = TLS_method();
	CliCTX = createSSLClientContext(HTTP_SSL_VERIFY);
	#ifdef HTTP_UTSNAME
	utsname os; if(!ckErr(uname(&os),"httpOSCheck {NON FATAL}")) {
		ServerStr += ((string)" (")+
		#if HTTP_SEND_NAME
		os.nodename+", "+
		#endif
		os.sysname+" "+(ARCH64?"x64":os.machine)+")";
	}
	#endif
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

SSL_CTX *createSSLClientContext(bool v) {
	SSL_CTX *ctx = SSL_CTX_new(CliSSL); if(!ctx) return 0;
	SSL_CTX_set_verify(ctx, v?SSL_VERIFY_PEER:SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify_depth(ctx, 10);
	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_COMPRESSION);
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
	thread([cli]() { WebSocket *ws; if(ws=cli->init()) ws->init(); }).detach();
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

HttpSocket::HttpSocket(HttpServer& s, Socket& c):srv(&s),cli(c),
name(s.name+"->"+c.addr.host+":"+to_string(c.addr.port)+" ("+to_string(c.sck)+")") {}

HttpSocket::HttpSocket(Socket& c):srv(0),cli(c),
name(string(c.addr.host)+":"+to_string(c.addr.port)+" ("+to_string(c.sck)+")") {}

WebSocket *HttpSocket::init() {
	#if HTTP_DEBUG
	cout << name+" Thread 0x" << hex << this_thread::get_id() << dec << '\n';
	#endif
	if(srv->sl) {
		int e; SSL *s=SSL_new((SSL_CTX*)srv->sl->s[0]);
		if(s) { SSL_set_fd(s,cli.sck); ssl=s; e=SSL_accept(s); }
		if(!s || e <= 0) {
			#if HTTP_DEBUG
			cout << name+" SSL Error " << SSL_get_error(s,e) << '\n';
			#endif
			cclose(); delete this; return 0;
		}
	}
	char b[HTTP_READ_SIZE]; char r,q=0; bool ka;
	while(!srv->st && (r=run(b)) != 3) {
		if(srv->opt.preRequest && !q) { //Pre-request:
			q=srv->opt.preRequest(*this,req,eRes);
			delete eRes; if(q==2) { delete req; break; }
			if(q==1) r=0; q=1;
		}
		if(!req) break; //Break on header parse error
		if(r==1 && !eRes) { //Create response
			auto ru=req->header.find("Upgrade");
			if(ru != req->header.end() && ru->second == "websocket") { //WebSocket Transfer
				if(srv->opt.wsPaths.find(req->path) == srv->opt.wsPaths.end()) {
					sendCode(401, "No Endpoint"); delete req; break;
				}
				uint8_t ver=strToUint(req->header["Sec-Websocket-Version"]);
				if(ver != 13 || req->header["Connection"] != "Upgrade") {
					sendCode(ver==13?400:405, "Bad Upgrade"); delete req; break;
				}
				HttpResponse res(*this,0); stringmap hd;
				hd["Upgrade"] = "websocket"; hd["Connection"] = "Upgrade";
				string hs = req->header["Sec-Websocket-Key"]+WS_UUID;
				uint8_t sha[SHA_DIGEST_LENGTH];
				SHA1((uint8_t*)hs.c_str(), hs.size(), (uint8_t*)&sha);
				hd["Sec-Websocket-Accept"] = Buffer((char*)sha,SHA_DIGEST_LENGTH).toBase64()+"=";
				res.writeHead(101, "WS", &hd); res.end();
				WebSocket *ws=new WebSocket(*this, req->path,ssl);
				delete req; cBuf.del(); delete this; return ws;
			} else if(srv->opt.onRequest) {
				q=0,ka=0; auto kh = req->header.find("Connection");
				if(kh != req->header.end()) ka = kh->second=="keep-alive";
				HttpResponse *res=new HttpResponse(*this,ka);
				srv->opt.onRequest(*req,*res); res->end();
				ka=res->kA; delete res;
			} else sendCode(204, "No Application");
			delete req; cBuf.del(); if(!ka) break;
		}
	}
	cclose(); cBuf.del(); delete this; return 0;
}

bool HttpSocket::initCli(bool https, HttpResFunc& cb) {
	if(https) {
		SSL *s = SSL_new(CliCTX); SSL_set_fd(s,cli.sck); ssl=s;
		SSL_set_tlsext_host_name(s,cli.addr.host.data());
		X509_VERIFY_PARAM *p = SSL_get0_param(s);
		X509_VERIFY_PARAM_set1_host(p,cli.addr.host.data(),0);
		if(SSL_connect(s) <= 0) {
			const char *es=ERR_error_string(ERR_get_error(),0);
			error("SSL "+name+": "+es,-1); cb(-5,0,0);
			cclose(); delete this; return 0;
		}
	}
	thread([this,cb]() {
		char b[HTTP_READ_SIZE]; char r;
		while(!(r=run(b)));
		if(r==1) cb(0,req,0); else if(r==2) {
			uint16_t s=eRes->getStat();
			string m=to_string(s)+" "+eRes->getStatMsg();
			cb(s,0,&m); delete eRes;
		} else cb(-6,0,0);
		cclose(); cBuf.del();
		delete req; delete this;
	}).detach(); return 1;
}

char HttpSocket::run(char *b) {
	ssize_t len=read(b, HTTP_READ_SIZE);
	if(len <= 0) return 3;
	#if HTTP_DEBUG > 2
	string s=string(b,len); replaceAll(s,"\r","<\\r>"); replaceAll(s,"\n","<\\n>\n");
	cout << "\n<<IN "+to_string(len)+"b "+name+">>\n"+s+"<<IN END>>\n";
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
	string t,u,hk,hv; stringmap hd; bool ph=1,nl=0; size_t cl=NPOS,cd=0;
	size_t i,o=0,sl=strlen(HTTP_NEWLINE); const char *rb=r.buf; chk=0;
	while((i=bFind(r,HTTP_NEWLINE,o)) != NPOS) {
		Buffer b=Buffer(rb+o,i-o); o=i+sl;
		if(ph) { //Parse Head:
			ph=0; vector<Buffer> h=bSplit(b," "); size_t hs=h.size();
			if(srv) { //Server Mode:
				if(hs != 3 || !h[2].match("HTTP/1.1")) { sendCode(400, "Invalid Request Head"); return 2; }
				if(h[1].len > 8000) { sendCode(414, "URI Too Long"); return 2; }
				t=h[0].toStr(); u=h[1].toStr(); if(u[0] != '/') { sendCode(400, "Invalid Request URI"); return 2; }
				if(t != "GET" && t != "POST" && t != "PUT" && t != "DELETE") {
					sendCode(405, "Unsupported Request Type"); return 2;
				}
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
				if(t == "GET") { sendCode(400, "GET w/ Content"); return 2; }
				cl=strToUint(hv); if(chk) { sendCode(400, "Chunked w/ Len"); return 2; }
				if(cl > (srv?HTTP_POST_MAX:HTTP_GET_MAX)) { sendCode(414, "Content Too Long"); return 2; }
			} else if(hk == "Content-Type" && startsWith(hv,"multipart")) { sendCode(405, "Multipart Unsupported"); return 2; }
			else if(hk == "Transfer-Encoding" && hv == "chunked") { chk=1; cl=0; } else hd[hk] = hv;
		}
	}
	if(!nl) { sendCode(400, "Premature Header End"); return 2; }
	if(cl == NPOS) {if(srv) cl=0; else { sendCode(400, "No Content-Len"); return 2; }}
	cOfs=0, cBuf=Buffer(cl), req=new HttpRequest(*this,t,u,hd,cd,cBuf);
	if(chk) {
		if(t == "GET") { sendCode(400, "Chunked GET"); return 2; }
		return parseChunk(r.buf+o,r.len-o);
	}
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
	if(cOfs+cd > (srv?HTTP_POST_MAX:HTTP_GET_MAX)) { cBuf.del(); sendCode(414, "Content Too Long"); return 2; }
	b=cBuf; cBuf=Buffer(cOfs+cd); memcpy((void*)cBuf.buf,b.buf,cOfs); b.del();
	return bCopy(buf,len,&rl)&&len-rl>2 ? parseChunk(buf+rl+2,len-rl-2):0;
}

void HttpSocket::cclose() {
	if(cli.err) return; cli.err=1; if(srv) srv->tx--; cli.close(); if(ssl) SSL_free((SSL*)ssl);
}
ssize_t HttpSocket::read(char *buf, size_t len) {
	if(cli.err) return 0;
	ssize_t r=ssl?SSL_read((SSL*)ssl,buf,len):cli.read(buf,len);
	if(r<=0) {
		#if HTTP_DEBUG
		if(!r || errno == EBADF) cout << name+" Connection Closed\n";
		else if(errno == EAGAIN) cout << name+" Timed Out\n";
		else if(errno == ECONNRESET) cout << name+" Connection Reset\n";
		#else
		if(!r || errno == EAGAIN || errno == ECONNRESET || errno == EBADF) {}
		#endif
		else error(name,r);
	}
	return r;
}
ssize_t HttpSocket::write(Buffer b) {
	if(cli.err) { b.del(); return 0; }
	#if HTTP_DEBUG > 2
	string s=b.toStr(); replaceAll(s,"\r","<\\r>"); replaceAll(s,"\n","<\\n>\n");
	cout << "\n<<OUT "+to_string(b.len)+"b "+name+">>\n"+s+"<<OUT END>>";
	#elif HTTP_DEBUG > 1
	cout << name+" OUT "+to_string(b.len);
	#endif
	ssize_t n=ssl?SSL_write((SSL*)ssl,b.buf,b.len):cli.write(b.buf,b.len);
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

//------------ WebSocket ------------

WebSocket::WebSocket(HttpSocket& c, string& p, void *ssl):srv(c.srv),
cli(c.cli),path(p),ssl(ssl),useMask(0),cb(c.srv->opt.wsPaths.find(p)->second),
name(srv->name+"->ws:"+cli.addr.host+":"+to_string(cli.addr.port)+p+" ("+to_string(cli.sck)+")") {}

void WebSocket::init() {
	#if HTTP_DEBUG
	cout << name+" Thread 0x" << hex << this_thread::get_id() << dec << '\n';
	#endif
	if(cli.setTimeout(HTTP_WS_TIMEOUT)) { delete this; return cclose(); }
	if(srv->opt.onWSConnect) srv->opt.onWSConnect(*this);
	run(); cclose(); msg.del();
	if(srv->opt.onWSDisconnect) srv->opt.onWSDisconnect(*this);
	delete this;
}

void WebSocket::end() {
	send(Buffer(),8); cli.err=1;
	//TODO: Send a close frame, wait 10 sec for response before force-closing
	//But don't wait here, because this could block forever if it's called in the run thread
	//ev.setTimeout([this](void *p) { cclose(); }, 10000);
	//ev.clearTimeout();
	cli.close();
}

void WebSocket::run() {
	char b[HTTP_READ_SIZE]; bool nc; ssize_t len,r;
	while(!srv->st) {
		if((len=read(b, HTTP_READ_SIZE))<=0) return;
		if((r=parseHdr(Buffer(b,len)))<=0) return error(name,r);
		len-=r; if(len > msg.len-mOfs) return error(name,-10); //Len Mismatch
		if(!msg.buf) { //Create Buffer
			if(!mOfs && len==msg.len) msg.buf=b+r,msg.db=0,r=0; else msg=Buffer(msg.len);
		}
		if(r) memcpy((void*)(msg.buf+mOfs),b+r,len); mOfs+=len;
		while(mOfs < msg.len) { //Gimme moar!
			if((len=read((char*)(msg.buf+mOfs), msg.len-mOfs))<=0) return;
			mOfs+=len;
		}
		if(fin) {
			if(mask) for(size_t i=0; i<msg.len; ++i)
				((uint8_t*)msg.buf)[i] = msg.buf[i]^((uint8_t*)&mask)[i%4];
			cb(*this); msg.del();
			if(op==8) { send(Buffer(),8); return; } //Close Frame
			op=0,mOfs=0;
		}
	}
}

ssize_t WebSocket::parseHdr(Buffer b) {
	if(b.len<3) return -2;
	fin=b.buf[0]>>7; uint8_t ofs=2; mask=b.buf[1]>>7;
	size_t len=b.buf[1]&127; if(!op) op=b.buf[0]&15;
	if(len==126) { //2-Byte Extended
		if(b.len<5) return -2;
		ofs=4, len=(size_t)b.buf[2]<<8, len|=b.buf[3];
	} else if(len==127) { //8-Byte Extended
		if(b.len<11) return -2;
		ofs=10, len=(size_t)b.buf[2]<<56, len|=(size_t)b.buf[3]<<48, len|=(size_t)b.buf[4]<<40,
			len|=(size_t)b.buf[5]<<32, len|=(size_t)b.buf[6]<<24, len|=(size_t)b.buf[7]<<16,
			len|=(size_t)b.buf[8]<<8, len|=b.buf[9];
	}
	if(mOfs+len > HTTP_WS_MAX) return -3; //Msg Too Long
	if(mask) {
		mask=*(uint32_t*)(b.buf+ofs), ofs+=4;
		if(!mask) return -4; //Bad Mask
	}
	if(!msg.buf) msg.len=len; else {
		Buffer ob=msg; msg=Buffer(ob.len+len);
		memcpy((void*)msg.buf, ob.buf, ob.len);
		mOfs=ob.len; ob.del();
	}
	return ofs;
}

ssize_t WebSocket::read(char *buf, size_t len) {
	if(cli.err==2) return 0;
	ssize_t r=ssl?SSL_read((SSL*)ssl,buf,len):cli.read(buf,len);
	if(r<=0) {
		#if HTTP_DEBUG
		if(!r || errno == EBADF) cout << name+" Connection Closed\n";
		else if(errno == EAGAIN) cout << name+" Timed Out\n";
		else if(errno == ECONNRESET) cout << name+" Connection Reset\n";
		#else
		if(!r || errno == EAGAIN || errno == ECONNRESET || errno == EBADF) {}
		#endif
		else error(name,-11);
	}
	return r;
}
ssize_t WebSocket::send(Buffer b, uint8_t op) {
	if(cli.err) return -2;
	uint8_t ofs=2;
	if(b.len>125) ofs=4; //2-Byte Extended
	else if(b.len>UINT16_MAX) ofs=10; //8-Byte Extended
	size_t l=b.len+ofs; char sb[l];
	if(b.len>125) sb[1]=126, sb[2]=b.len>>8, sb[3]=b.len;
	else if(b.len>UINT16_MAX) sb[1]=127, sb[2]=b.len>>56, sb[3]=b.len>>48, sb[4]=b.len>>40,
		sb[5]=b.len>>32, sb[6]=b.len>>24, sb[7]=b.len>>16, sb[8]=b.len>>8, sb[9]=b.len;
	else sb[1]=b.len;
	sb[0]=128|(op&15);
	if(useMask) { //Mask Bytes
		sb[1]|=128; if(RAND_bytes((uint8_t*)&mask,4)<1) return error(name,-14),-14;
		for(size_t i=0; i<b.len; ++i) (sb+ofs)[i] = b.buf[i] ^ ((uint8_t*)&mask)[i%4];
	} else memcpy(sb+ofs, b.buf, b.len);
	ssize_t n=ssl?SSL_write((SSL*)ssl,sb,l):cli.write(sb,l);
	if(n!=l) error(name,-15); return n;
}
void WebSocket::cclose() {
	if(cli.err==2) return; cli.err=2;
	if(srv) srv->tx--; cli.close(); if(ssl) SSL_free((SSL*)ssl);
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
	if(!write("<title>"+m+"</title><body style='background:#111;color:#ccc;font:16pt sans-serif;text-align:center'><pre>"+m+"</pre>"+(desc.size()?"<p>"+desc+"</p>":"")+"</body>")) return 0;
	return end();
}

bool HttpResponse::writeHead(uint16_t code, string status, stringmap *headers) { //Server Mode
	if(cm || ended || code < 100 || code > 999 || (uC && stat)) return 0;
	if(uC && (code < 200 || code == 204 || code >= 300 && code < 400)) return 0;
	stat=code, sMsg=status, hdr=headers?(uC?headers:new stringmap(*headers)):0;
	if(uC && cli.write(genHeader()) <= 0) return 0;
	return 1;
}

bool HttpResponse::writeHead(const char *path, const char *method, stringmap *headers) { //Client Mode
	if(!cm || ended || (uC && stat)) return 0;
	stat=1; if(!path) path="/"; if(!method) method="GET";
	cm=Append::str(method,path[0]=='/'?" ":" /",path);
	hdr=headers?(uC?headers:new stringmap(*headers)):0;
	if(uC && cli.write(genHeader()) <= 0) return 0;
	return 1;
}

bool HttpResponse::write(Buffer b) {
	if(ended || !b.buf) return 0;
	bool s=1; const char *d=b.db; b.db=0;
	if(uC) { if(!stat || cli.write(genChunk(b)) <= 0) s=0; }
	else cont=Append::buf(cont,b);
	b.db=d; return s;
}

Buffer HttpResponse::genHeader() {
	stringmap& hd=*(hdr?hdr:new stringmap()); bool cl;
	if(cm) {
		cl=cont.len; auto hf=hd.find("Host");
		if(hf == hd.end()) hd["Host"] = cli.cli.addr.host;
	} else {
		if(stat != 304) hd["Server"] = ServerStr;
		#if HTTP_NO_CORS
		hd["X-Frame-Options"] = "sameorigin";
		#endif
		cl = !(stat < 200 || stat == 204 || stat >= 300 && stat < 400);
	}
	if(gzip) hd["Content-Encoding"] = gzip==2?"deflate":"gzip";
	if(uC) hd["Transfer-Encoding"] = "chunked";
	else if(cl) hd["Content-Length"] = to_string(cont.len); else cont.del();
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
	string msg; if(sMsg.size()) { msg=" "+sMsg; replaceAll(msg,"\n"," "); }
	Buffer hb=cm?Append::buf(cl?"GET /":cm," HTTP/1.1",msg,HTTP_NEWLINE,h,HTTP_NEWLINE,cont):
		Append::buf("HTTP/1.1 ",stat,msg,HTTP_NEWLINE,h,HTTP_NEWLINE,cont);
	if(cm && !cl) delete[] cm; if(uC||!hdr) delete &hd;
	return hb;
}

bool HttpResponse::end() {
	if(ended) return 0; if(!stat && !cm) writeHead(uC||!cont.len?204:200);
	bool s=cli.write(uC?genChunk(Buffer()):genHeader()) <= 0;
	ended=1; return s;
}

}