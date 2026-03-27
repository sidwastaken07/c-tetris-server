/*
 * TETRIS - C WebSocket Server (Windows)
 *
 * Compile:  gcc -o tetris_server tetris_server.c -lws2_32 -O2
 * Run:      tetris_server.exe
 * Browser:  http://localhost:3000
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#pragma comment(lib,"ws2_32.lib")

/* ============================================================
   SHA-1  (no OpenSSL needed)
   ============================================================ */
typedef struct { uint32_t s[5],n[2]; uint8_t b[64]; } SHA1;
#define R32(v,n) (((v)<<(n))|((v)>>(32-(n))))
static void sha1_block(SHA1 *x, const uint8_t *p){
    uint32_t w[80],a,b,c,d,e,t,i;
    for(i=0;i<16;i++) w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
    for(i=16;i<80;i++) w[i]=R32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1);
    a=x->s[0];b=x->s[1];c=x->s[2];d=x->s[3];e=x->s[4];
#define ST(f,k) t=R32(a,5)+(f)+e+(k)+w[i];e=d;d=c;c=R32(b,30);b=a;a=t
    for(i=0;i<20;i++){ST((b&c)|(~b&d),0x5A827999);}
    for(i=20;i<40;i++){ST(b^c^d,0x6ED9EBA1);}
    for(i=40;i<60;i++){ST((b&c)|(b&d)|(c&d),0x8F1BBCDC);}
    for(i=60;i<80;i++){ST(b^c^d,0xCA62C1D6);}
#undef ST
    x->s[0]+=a;x->s[1]+=b;x->s[2]+=c;x->s[3]+=d;x->s[4]+=e;
}
static void sha1_init(SHA1 *x){x->s[0]=0x67452301;x->s[1]=0xEFCDAB89;x->s[2]=0x98BADCFE;x->s[3]=0x10325476;x->s[4]=0xC3D2E1F0;x->n[0]=x->n[1]=0;}
static void sha1_feed(SHA1 *x, const void *data, size_t len){
    const uint8_t *d=(const uint8_t*)data;
    uint32_t j=(x->n[0]>>3)&63;
    if((x->n[0]+=(uint32_t)(len<<3))<(uint32_t)(len<<3))x->n[1]++;
    x->n[1]+=(uint32_t)(len>>29);
    size_t i=0;
    if(len+j>=64){memcpy(x->b+j,d,64-j);sha1_block(x,x->b);i=64-j;j=0;for(;i+63<len;i+=64)sha1_block(x,d+i);}
    memcpy(x->b+j,d+i,len-i);
}
static void sha1_done(SHA1 *x, uint8_t out[20]){
    uint8_t fc[8];int i;
    fc[0]=(uint8_t)(x->n[1]>>24);fc[1]=(uint8_t)(x->n[1]>>16);fc[2]=(uint8_t)(x->n[1]>>8);fc[3]=(uint8_t)x->n[1];
    fc[4]=(uint8_t)(x->n[0]>>24);fc[5]=(uint8_t)(x->n[0]>>16);fc[6]=(uint8_t)(x->n[0]>>8);fc[7]=(uint8_t)x->n[0];
    uint8_t p=0x80; sha1_feed(x,&p,1);
    p=0; while((x->n[0]>>3)%64!=56) sha1_feed(x,&p,1);
    sha1_feed(x,fc,8);
    for(i=0;i<20;i++) out[i]=(uint8_t)(x->s[i>>2]>>((3-(i&3))*8));
}
static const char B64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static void b64(const uint8_t *in,int len,char *out){
    int i,j=0;
    for(i=0;i<len;i+=3){
        uint32_t v=((uint32_t)in[i]<<16)|((i+1<len?(uint32_t)in[i+1]:0)<<8)|(i+2<len?(uint32_t)in[i+2]:0);
        out[j++]=B64[(v>>18)&63];out[j++]=B64[(v>>12)&63];
        out[j++]=(i+1<len)?B64[(v>>6)&63]:'=';out[j++]=(i+2<len)?B64[v&63]:'=';
    }out[j]=0;
}

/* ============================================================
   Tetris game (all logic in C)
   ============================================================ */
#define ROWS 20
#define COLS 10
static const int SHAPES[7][4][4][2]={
    {{{1,0},{1,1},{1,2},{1,3}},{{0,2},{1,2},{2,2},{3,2}},{{2,0},{2,1},{2,2},{2,3}},{{0,1},{1,1},{2,1},{3,1}}},
    {{{0,0},{0,1},{1,0},{1,1}},{{0,0},{0,1},{1,0},{1,1}},{{0,0},{0,1},{1,0},{1,1}},{{0,0},{0,1},{1,0},{1,1}}},
    {{{0,1},{1,0},{1,1},{1,2}},{{0,1},{1,1},{1,2},{2,1}},{{1,0},{1,1},{1,2},{2,1}},{{0,1},{1,0},{1,1},{2,1}}},
    {{{0,1},{0,2},{1,0},{1,1}},{{0,1},{1,1},{1,2},{2,2}},{{1,1},{1,2},{2,0},{2,1}},{{0,0},{1,0},{1,1},{2,1}}},
    {{{0,0},{0,1},{1,1},{1,2}},{{0,2},{1,1},{1,2},{2,1}},{{1,0},{1,1},{2,1},{2,2}},{{0,1},{1,0},{1,1},{2,0}}},
    {{{0,0},{1,0},{1,1},{1,2}},{{0,1},{0,2},{1,1},{2,1}},{{1,0},{1,1},{1,2},{2,2}},{{0,1},{1,1},{2,0},{2,1}}},
    {{{0,2},{1,0},{1,1},{1,2}},{{0,1},{1,1},{2,1},{2,2}},{{1,0},{1,1},{1,2},{2,0}},{{0,0},{0,1},{1,1},{2,1}}}
};
typedef struct{
    int board[ROWS][COLS];
    int ct,cr,cy,cx; /* current type,rot,row,col */
    int nt;          /* next type */
    int score,level,lines,over,started,paused;
} TGame;
static TGame G;

static int ok(int t,int r,int y,int x){
    int i; for(i=0;i<4;i++){int rr=y+SHAPES[t][r][i][0],cc=x+SHAPES[t][r][i][1];if(rr<0||rr>=ROWS||cc<0||cc>=COLS||G.board[rr][cc]!=-1)return 0;}return 1;
}
static void do_spawn(void){
    G.ct=G.nt; G.nt=rand()%7; G.cr=0; G.cy=0; G.cx=COLS/2-2;
    if(!ok(G.ct,G.cr,G.cy,G.cx)) G.over=1;
}
static void do_lock(void){
    int i,r,cl=0;
    for(i=0;i<4;i++) G.board[G.cy+SHAPES[G.ct][G.cr][i][0]][G.cx+SHAPES[G.ct][G.cr][i][1]]=G.ct;
    for(r=ROWS-1;r>=0;r--){
        int full=1,c; for(c=0;c<COLS;c++) if(G.board[r][c]==-1){full=0;break;}
        if(full){cl++;int rr; for(rr=r;rr>0;rr--) memcpy(G.board[rr],G.board[rr-1],COLS*sizeof(int));
            memset(G.board[0],-1,COLS*sizeof(int));r++;}
    }
    {const int pts[]={0,100,300,500,800};G.lines+=cl;G.score+=pts[cl]*G.level;G.level=G.lines/10+1;}
    do_spawn();
}
static void game_init(void){
    int r,c; for(r=0;r<ROWS;r++) for(c=0;c<COLS;c++) G.board[r][c]=-1;
    G.score=G.lines=0;G.level=1;G.over=G.paused=0;G.started=1;G.nt=rand()%7;do_spawn();
}
static void game_tick(void){
    if(!G.started||G.over||G.paused)return;
    if(ok(G.ct,G.cr,G.cy+1,G.cx))G.cy++; else do_lock();
}
static void game_key(const char *cmd){
    if(strcmp(cmd,"START")==0){game_init();return;}
    if(!G.started||G.over)return;
    if(strcmp(cmd,"PAUSE")==0){G.paused=!G.paused;return;}
    if(G.paused)return;
    if     (!strcmp(cmd,"LEFT")) {if(ok(G.ct,G.cr,G.cy,G.cx-1))G.cx--;}
    else if(!strcmp(cmd,"RIGHT")){if(ok(G.ct,G.cr,G.cy,G.cx+1))G.cx++;}
    else if(!strcmp(cmd,"DOWN")) {if(ok(G.ct,G.cr,G.cy+1,G.cx))G.cy++;else do_lock();}
    else if(!strcmp(cmd,"ROTATE")){
        int nr=(G.cr+1)%4;
        if     (ok(G.ct,nr,G.cy,G.cx))  G.cr=nr;
        else if(ok(G.ct,nr,G.cy,G.cx+1)){G.cr=nr;G.cx++;}
        else if(ok(G.ct,nr,G.cy,G.cx-1)){G.cr=nr;G.cx--;}
    }
    else if(!strcmp(cmd,"HARD")){while(ok(G.ct,G.cr,G.cy+1,G.cx))G.cy++;do_lock();}
}
static int game_json(char *buf,int max){
    char bs[ROWS*COLS*4+16]; int bp=0,r,c;
    bs[bp++]='[';
    for(r=0;r<ROWS;r++) for(c=0;c<COLS;c++){
        bp+=snprintf(bs+bp,(int)sizeof(bs)-bp,"%d",G.board[r][c]);
        if(r*COLS+c<ROWS*COLS-1)bs[bp++]=',';
    }
    bs[bp++]=']';bs[bp]=0;
    char ps[64];int pp=0; ps[pp++]='[';
    if(!G.over&&G.started){int i; for(i=0;i<4;i++){int rr=G.cy+SHAPES[G.ct][G.cr][i][0],cc=G.cx+SHAPES[G.ct][G.cr][i][1];pp+=snprintf(ps+pp,(int)sizeof(ps)-pp,"%s[%d,%d]",i?",":"",rr,cc);}}
    ps[pp++]=']';ps[pp]=0;
    int gy=G.cy;
    if(!G.over&&G.started) while(ok(G.ct,G.cr,gy+1,G.cx))gy++;
    char gs[64];int gp=0; gs[gp++]='[';
    if(!G.over&&G.started&&gy!=G.cy){int i; for(i=0;i<4;i++){int rr=gy+SHAPES[G.ct][G.cr][i][0],cc=G.cx+SHAPES[G.ct][G.cr][i][1];gp+=snprintf(gs+gp,(int)sizeof(gs)-gp,"%s[%d,%d]",i?",":"",rr,cc);}}
    gs[gp++]=']';gs[gp]=0;
    return snprintf(buf,max,
        "{\"board\":%s,\"piece\":%s,\"pieceType\":%d,\"ghost\":%s,"
        "\"next\":%d,\"score\":%d,\"level\":%d,\"lines\":%d,"
        "\"gameOver\":%s,\"started\":%s,\"paused\":%s}",
        bs,ps,G.ct,gs,G.nt,G.score,G.level,G.lines,
        G.over?"true":"false",G.started?"true":"false",G.paused?"true":"false");
}

/* ============================================================
   WebSocket helpers
   ============================================================ */
static int ws_upgrade(SOCKET fd, const char *req){
    /* find key */
    const char *k=strstr(req,"Sec-WebSocket-Key:");
    if(!k){k=strstr(req,"sec-websocket-key:");} /* case fallback */
    if(!k){printf("[WS] no key found in headers\n");return -1;}
    k+=18; while(*k==' '||*k=='\t')k++;
    char key[128]={0}; int ki=0;
    while(k[ki]&&k[ki]!='\r'&&k[ki]!='\n'&&ki<(int)sizeof(key)-1){key[ki]=k[ki];ki++;}
    /* strip trailing spaces */
    while(ki>0&&(key[ki-1]==' '||key[ki-1]=='\t'))ki--;
    key[ki]=0;
    printf("[WS] key='%s'\n",key);
    char combo[256];
    snprintf(combo,sizeof(combo),"%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11",key);
    SHA1 ctx; uint8_t dig[20]; char acc[32];
    sha1_init(&ctx); sha1_feed(&ctx,(uint8_t*)combo,strlen(combo)); sha1_done(&ctx,dig);
    b64(dig,20,acc);
    char resp[512];
    int rl=snprintf(resp,sizeof(resp),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n\r\n",acc);
    int sent=send(fd,resp,rl,0);
    printf("[WS] handshake sent %d bytes, accept='%s'\n",sent,acc);
    return (sent==rl)?0:-1;
}
static void ws_write(SOCKET fd,const char *msg,int len){
    uint8_t hdr[4];int hl=2;
    hdr[0]=0x81;
    if(len<=125){hdr[1]=(uint8_t)len;}
    else{hdr[1]=126;hdr[2]=(uint8_t)(len>>8);hdr[3]=(uint8_t)(len&0xFF);hl=4;}
    send(fd,(char*)hdr,hl,0); send(fd,msg,len,0);
}
static int ws_read(SOCKET fd,char *out,int max){
    uint8_t hd[2];
    int n=recv(fd,(char*)hd,2, MSG_WAITALL);
    if(n<=0)return -1;
    int op=hd[0]&0x0F; if(op==8)return -1;
    int masked=(hd[1]&0x80)!=0, plen=hd[1]&0x7F;
    if(plen==126){uint8_t e[2];recv(fd,(char*)e,2,MSG_WAITALL);plen=(e[0]<<8)|e[1];}
    uint8_t mask[4]={0}; if(masked)recv(fd,(char*)mask,4,MSG_WAITALL);
    if(plen>=max)plen=max-1;
    int got=recv(fd,out,plen,MSG_WAITALL); if(got<=0)return -1;
    if(masked){int i; for(i=0;i<got;i++)out[i]^=mask[i%4];}
    out[got]=0; return got;
}

/* ============================================================
   Embedded HTML page
   ============================================================ */
static const char PAGE[]=
"<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>TETRIS</title>"
"<link href='https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap' rel='stylesheet'>"
"<style>"
":root{--bg:#0a0a0f;--panel:#0f0f1a;--border:#1a1a2e;--acc:#00f5ff;--acc2:#ff006e;}"
"*{margin:0;padding:0;box-sizing:border-box;}"
"body{background:var(--bg);color:#fff;font-family:'Share Tech Mono',monospace;"
"min-height:100vh;display:flex;align-items:center;justify-content:center;overflow:hidden;}"
"body::before{content:'';position:fixed;inset:0;pointer-events:none;"
"background:repeating-linear-gradient(0deg,transparent,transparent 40px,rgba(255,255,255,.03) 40px,rgba(255,255,255,.03) 41px),"
"repeating-linear-gradient(90deg,transparent,transparent 40px,rgba(255,255,255,.03) 40px,rgba(255,255,255,.03) 41px);}"
".wrap{position:relative;z-index:1;display:flex;gap:24px;align-items:flex-start;}"
".side{width:160px;display:flex;flex-direction:column;gap:20px;}"
".box{background:var(--panel);border:1px solid var(--border);padding:16px;position:relative;}"
".box::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;"
"background:linear-gradient(90deg,transparent,var(--acc),transparent);}"
".lbl{font-family:'Orbitron',sans-serif;font-size:9px;letter-spacing:3px;color:var(--acc);margin-bottom:8px;opacity:.7;}"
".val{font-family:'Orbitron',sans-serif;font-size:22px;font-weight:700;text-shadow:0 0 20px var(--acc);}"
".title{font-family:'Orbitron',sans-serif;font-size:11px;font-weight:900;letter-spacing:8px;"
"color:var(--acc);text-align:center;text-shadow:0 0 30px var(--acc);margin-bottom:4px;}"
".sub{font-size:9px;color:rgba(255,255,255,.2);letter-spacing:2px;text-align:center;margin-bottom:12px;}"
".cc{position:relative;}"
".cc::before{content:'';position:absolute;inset:-1px;z-index:-1;background-size:300% 300%;"
"background:linear-gradient(135deg,var(--acc),var(--acc2),var(--acc));animation:ab 4s linear infinite;}"
"@keyframes ab{0%{background-position:0 50%}50%{background-position:100% 50%}100%{background-position:0 50%}}"
"canvas{display:block;}#gc{background:#060610;}"
".ctrl{font-size:10px;line-height:1.9;color:rgba(255,255,255,.4);}"
".ctrl span{color:var(--acc);font-weight:bold;}"
"#ov{position:absolute;inset:0;background:rgba(6,6,16,.93);display:flex;flex-direction:column;"
"align-items:center;justify-content:center;z-index:10;backdrop-filter:blur(4px);}"
"#ov h2{font-family:'Orbitron',sans-serif;font-size:28px;font-weight:900;letter-spacing:6px;"
"color:var(--acc);text-shadow:0 0 40px var(--acc);margin-bottom:12px;}"
"#ov p{font-size:11px;color:rgba(255,255,255,.5);letter-spacing:3px;margin-bottom:8px;}"
".fs{font-family:'Orbitron',sans-serif;font-size:36px;font-weight:700;"
"color:var(--acc2);text-shadow:0 0 30px var(--acc2);margin:16px 0;}"
".btn{margin-top:20px;background:transparent;border:1px solid var(--acc);color:var(--acc);"
"font-family:'Orbitron',sans-serif;font-size:11px;letter-spacing:4px;padding:12px 32px;cursor:pointer;transition:all .2s;}"
".btn:hover{background:var(--acc);color:var(--bg);}"
"#status{position:fixed;bottom:12px;left:50%;transform:translateX(-50%);"
"font-size:10px;color:rgba(255,255,255,.3);letter-spacing:2px;}"
"</style></head><body>"
"<div class='wrap'>"
"<div class='side'>"
"<div><div class='title'>TETRIS</div><div class='sub'>C SERVER</div></div>"
"<div class='box'><div class='lbl'>Score</div><div class='val' id='sc'>0</div></div>"
"<div class='box'><div class='lbl'>Level</div><div class='val' id='lv'>1</div></div>"
"<div class='box'><div class='lbl'>Lines</div><div class='val' id='ln'>0</div></div>"
"</div>"
"<div class='cc'>"
"<canvas id='gc' width='300' height='600'></canvas>"
"<div id='ov'>"
"<h2>TETRIS</h2><p>POWERED BY C</p>"
"<button class='btn' id='sb'>START GAME</button>"
"<p style='margin-top:24px;font-size:9px;opacity:.3'>&#8592;&#8594; MOVE &nbsp; &#8593; ROTATE &nbsp; &#8595; DROP &nbsp; SPC SLAM</p>"
"</div>"
"</div>"
"<div class='side'>"
"<div class='box'><div class='lbl'>Next</div><canvas id='nc' width='120' height='80'></canvas></div>"
"<div class='box'><div class='lbl'>Controls</div>"
"<div class='ctrl'>"
"<span>&#8592;&#8594;</span> Move<br>"
"<span>&#8593;</span> Rotate<br>"
"<span>&#8595;</span> Soft drop<br>"
"<span>SPC</span> Hard drop<br>"
"<span>P</span> Pause"
"</div></div>"
"</div>"
"</div>"
"<div id='status'>CONNECTING...</div>"
"<script>"
"const COL=['#00f5ff','#ffe600','#bf5fff','#00ff87','#ff3860','#3d6fff','#ff8c00'];"
"const GLO=['rgba(0,245,255,.5)','rgba(255,230,0,.5)','rgba(191,95,255,.5)','rgba(0,255,135,.5)','rgba(255,56,96,.5)','rgba(61,111,255,.5)','rgba(255,140,0,.5)'];"
"const SHP=["
"[[[1,0],[1,1],[1,2],[1,3]],[[0,2],[1,2],[2,2],[3,2]],[[2,0],[2,1],[2,2],[2,3]],[[0,1],[1,1],[2,1],[3,1]]],"
"[[[0,0],[0,1],[1,0],[1,1]],[[0,0],[0,1],[1,0],[1,1]],[[0,0],[0,1],[1,0],[1,1]],[[0,0],[0,1],[1,0],[1,1]]],"
"[[[0,1],[1,0],[1,1],[1,2]],[[0,1],[1,1],[1,2],[2,1]],[[1,0],[1,1],[1,2],[2,1]],[[0,1],[1,0],[1,1],[2,1]]],"
"[[[0,1],[0,2],[1,0],[1,1]],[[0,1],[1,1],[1,2],[2,2]],[[1,1],[1,2],[2,0],[2,1]],[[0,0],[1,0],[1,1],[2,1]]],"
"[[[0,0],[0,1],[1,1],[1,2]],[[0,2],[1,1],[1,2],[2,1]],[[1,0],[1,1],[2,1],[2,2]],[[0,1],[1,0],[1,1],[2,0]]],"
"[[[0,0],[1,0],[1,1],[1,2]],[[0,1],[0,2],[1,1],[2,1]],[[1,0],[1,1],[1,2],[2,2]],[[0,1],[1,1],[2,0],[2,1]]],"
"[[[0,2],[1,0],[1,1],[1,2]],[[0,1],[1,1],[2,1],[2,2]],[[1,0],[1,1],[1,2],[2,0]],[[0,0],[0,1],[1,1],[2,1]]]];"
"const gc=document.getElementById('gc'),ctx=gc.getContext('2d');"
"const nc=document.getElementById('nc'),nctx=nc.getContext('2d');"
"const ov=document.getElementById('ov'),st=document.getElementById('status');"
"const B=30,R=20,C=10;"
"let S=null,ws=null;"

/* WebSocket connect with retry */
"function connect(){"
"  st.textContent='CONNECTING...';"
"  ws=new WebSocket('ws://'+location.host);"
"  ws.onopen=function(){"
"    st.textContent='CONNECTED TO C SERVER';"
"    setTimeout(()=>st.style.opacity='0',2000);"
"  };"
"  ws.onmessage=function(e){"
"    S=JSON.parse(e.data);render();"
"    if(S.gameOver)showOver();"
"  };"
"  ws.onerror=function(e){"
"    st.textContent='WS ERROR - retrying...';"
"    st.style.opacity='1';"
"  };"
"  ws.onclose=function(){"
"    st.textContent='DISCONNECTED - reconnecting...';"
"    st.style.opacity='1';"
"    setTimeout(connect,1500);"
"  };"
"}"
"connect();"

"function send(cmd){"
"  if(ws&&ws.readyState===1)ws.send(cmd);"
"}"

"document.getElementById('sb').onclick=function(){"
"  send('START');ov.style.display='none';"
"};"

"document.addEventListener('keydown',function(e){"
"  if(!S||!S.started)return;"
"  var m={ArrowLeft:'LEFT',ArrowRight:'RIGHT',ArrowUp:'ROTATE',ArrowDown:'DOWN'};"
"  if(e.key===' '){e.preventDefault();send('HARD');return;}"
"  if(e.key==='p'||e.key==='P'){send('PAUSE');return;}"
"  var c=m[e.key];if(c){e.preventDefault();send(c);}"
"});"

"function showOver(){"
"  ov.innerHTML=\"<h2>GAME OVER</h2><p>FINAL SCORE</p><div class='fs'>\"+S.score+\"</div><button class='btn' id='rb'>PLAY AGAIN</button>\";"
"  ov.style.display='flex';"
"  document.getElementById('rb').onclick=function(){send('START');ov.style.display='none';};"
"}"

"function drawBlk(cx,r,c,t,a){"
"  a=a===undefined?1:a;"
"  var x=c*B,y=r*B;"
"  cx.globalAlpha=a;cx.shadowColor=GLO[t];cx.shadowBlur=12;"
"  cx.fillStyle=COL[t];cx.fillRect(x+1,y+1,B-2,B-2);"
"  cx.shadowBlur=0;"
"  cx.fillStyle='rgba(255,255,255,.25)';cx.fillRect(x+1,y+1,B-2,4);cx.fillRect(x+1,y+1,4,B-2);"
"  cx.fillStyle='rgba(0,0,0,.3)';cx.fillRect(x+1,y+B-5,B-2,4);cx.fillRect(x+B-5,y+1,4,B-2);"
"  cx.globalAlpha=1;cx.shadowBlur=0;"
"}"

"function render(){"
"  if(!S)return;"
"  ctx.clearRect(0,0,300,600);"
"  ctx.strokeStyle='rgba(255,255,255,.03)';ctx.lineWidth=1;"
"  for(var r=0;r<=R;r++){ctx.beginPath();ctx.moveTo(0,r*B);ctx.lineTo(C*B,r*B);ctx.stroke();}"
"  for(var c=0;c<=C;c++){ctx.beginPath();ctx.moveTo(c*B,0);ctx.lineTo(c*B,R*B);ctx.stroke();}"
"  for(var r=0;r<R;r++)for(var c=0;c<C;c++){var t=S.board[r*C+c];if(t!==-1)drawBlk(ctx,r,c,t);}"
"  if(S.ghost){for(var i=0;i<S.ghost.length;i++){var rc=S.ghost[i];"
"    ctx.globalAlpha=.15;ctx.fillStyle=COL[S.pieceType];"
"    ctx.fillRect(rc[1]*B+1,rc[0]*B+1,B-2,B-2);"
"    ctx.strokeStyle=COL[S.pieceType];ctx.lineWidth=1;"
"    ctx.strokeRect(rc[1]*B+1,rc[0]*B+1,B-2,B-2);ctx.globalAlpha=1;}}"
"  if(S.piece){for(var i=0;i<S.piece.length;i++){var rc=S.piece[i];drawBlk(ctx,rc[0],rc[1],S.pieceType);}}"
"  document.getElementById('sc').textContent=S.score;"
"  document.getElementById('lv').textContent=S.level;"
"  document.getElementById('ln').textContent=S.lines;"
"  drawNext();"
"}"

"function drawNext(){"
"  if(!S)return;"
"  nctx.clearRect(0,0,120,80);"
"  var p=SHP[S.next][0];"
"  var minR=99,minC=99,maxC=0;"
"  for(var i=0;i<p.length;i++){if(p[i][0]<minR)minR=p[i][0];if(p[i][1]<minC)minC=p[i][1];if(p[i][1]>maxC)maxC=p[i][1];}"
"  var ox=(120-(maxC-minC+1)*24)/2,oy=12;"
"  for(var i=0;i<p.length;i++){"
"    var x=(p[i][1]-minC)*24+ox,y=(p[i][0]-minR)*24+oy;"
"    nctx.shadowColor=GLO[S.next];nctx.shadowBlur=10;"
"    nctx.fillStyle=COL[S.next];nctx.fillRect(x+1,y+1,22,22);"
"    nctx.shadowBlur=0;"
"    nctx.fillStyle='rgba(255,255,255,.2)';nctx.fillRect(x+1,y+1,22,4);nctx.fillRect(x+1,y+1,4,22);"
"  }"
"}"
"</script></body></html>";

/* ============================================================
   Client table + broadcast
   ============================================================ */
#define MAX_CL 8
static SOCKET cli[MAX_CL];
static int    cli_up[MAX_CL]; /* 1 = websocket upgraded */

static void broadcast(void){
    char json[4096]; int jlen=game_json(json,sizeof(json));
    int i; for(i=0;i<MAX_CL;i++) if(cli[i]!=INVALID_SOCKET&&cli_up[i]) ws_write(cli[i],json,jlen);
}

/* recv all available HTTP headers (loop until \r\n\r\n) */
static int recv_http(SOCKET fd, char *buf, int max){
    int total=0;
    memset(buf,0,max);
    while(total<max-1){
        int n=recv(fd,buf+total,1,0);
        if(n<=0)break;
        total+=n;
        if(total>=4&&memcmp(buf+total-4,"\r\n\r\n",4)==0)break;
    }
    buf[total]=0;
    return total;
}

/* ============================================================
   Main
   ============================================================ */
int main(void){
    int i;
    srand((unsigned)time(NULL));
    memset(&G,0,sizeof(G));

    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    for(i=0;i<MAX_CL;i++) cli[i]=INVALID_SOCKET;

    SOCKET srv=socket(AF_INET,SOCK_STREAM,0);
    if(srv==INVALID_SOCKET){printf("socket() failed\n");return 1;}
    int opt=1; setsockopt(srv,SOL_SOCKET,SO_REUSEADDR,(char*)&opt,sizeof(opt));

    struct sockaddr_in addr; memset(&addr,0,sizeof(addr));
    addr.sin_family=AF_INET; addr.sin_port=htons(3000); addr.sin_addr.s_addr=INADDR_ANY;
    if(bind(srv,(struct sockaddr*)&addr,sizeof(addr))!=0){printf("bind failed: %d\n",WSAGetLastError());return 1;}
    listen(srv,10);

    /* non-blocking accept */
    u_long nb=1; ioctlsocket(srv,FIONBIO,&nb);

    printf("\n");
    printf("  ████████╗███████╗████████╗██████╗ ██╗███████╗\n");
    printf("     ██╔══╝██╔════╝╚══██╔══╝██╔══██╗██║██╔════╝\n");
    printf("     ██║   █████╗     ██║   ██████╔╝██║███████╗\n");
    printf("     ██║   ██╔══╝     ██║   ██╔══██╗██║╚════██║\n");
    printf("     ██║   ███████╗   ██║   ██║  ██║██║███████║\n");
    printf("     ╚═╝   ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚══════╝\n");
    printf("\n  C WebSocket Server running on port 3000\n");
    printf("  Open your browser: http://localhost:3000\n\n");

    DWORD last=GetTickCount();

    while(1){
        /* Accept new connection */
        struct sockaddr_in ca; int cl=(int)sizeof(ca);
        SOCKET nfd=accept(srv,(struct sockaddr*)&ca,(int*)&cl);
        if(nfd!=INVALID_SOCKET){
            /* switch to blocking for HTTP read */
            u_long b0=0; ioctlsocket(nfd,FIONBIO,&b0);

            /* set receive timeout 2s */
            DWORD tv2=2000; setsockopt(nfd,SOL_SOCKET,SO_RCVTIMEO,(char*)&tv2,sizeof(tv2));

            char req[4096]; int rlen=recv_http(nfd,req,sizeof(req));
            printf("[HTTP] %d bytes received\n",rlen);

            if(rlen>0&&(strstr(req,"Upgrade: websocket")||strstr(req,"Upgrade: WebSocket"))){
                printf("[WS] upgrading connection\n");
                if(ws_upgrade(nfd,req)==0){
                    int slot=-1;
                    for(i=0;i<MAX_CL;i++) if(cli[i]==INVALID_SOCKET){slot=i;break;}
                    if(slot>=0){
                        /* non-blocking for game loop */
                        u_long nb2=1; ioctlsocket(nfd,FIONBIO,&nb2);
                        cli[slot]=nfd; cli_up[slot]=1;
                        printf("[WS] client connected in slot %d\n",slot);
                    } else { closesocket(nfd); printf("[WS] no free slots\n"); }
                } else { closesocket(nfd); printf("[WS] handshake failed\n"); }
            } else if(rlen>0){
                /* Serve HTML page */
                char hdr[256];
                int hl=snprintf(hdr,sizeof(hdr),
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html; charset=utf-8\r\n"
                    "Content-Length: %d\r\n"
                    "Connection: close\r\n\r\n",(int)strlen(PAGE));
                send(nfd,hdr,hl,0);
                send(nfd,PAGE,(int)strlen(PAGE),0);
                closesocket(nfd);
                printf("[HTTP] page served\n");
            } else {
                closesocket(nfd);
            }
        }

        /* Read messages from websocket clients */
        for(i=0;i<MAX_CL;i++){
            if(cli[i]==INVALID_SOCKET||!cli_up[i])continue;
            fd_set rs; FD_ZERO(&rs); FD_SET(cli[i],&rs);
            struct timeval tv={0,0};
            if(select(0,&rs,NULL,NULL,&tv)>0){
                char msg[64];
                int n=ws_read(cli[i],msg,sizeof(msg));
                if(n<0){
                    printf("[WS] client %d disconnected\n",i);
                    closesocket(cli[i]); cli[i]=INVALID_SOCKET; cli_up[i]=0;
                } else {
                    printf("[WS] cmd='%s'\n",msg);
                    game_key(msg); broadcast();
                }
            }
        }

        /* Gravity tick */
        DWORD now=GetTickCount();
        int interval=500-(G.level-1)*40; if(interval<80)interval=80;
        if((int)(now-last)>=interval){
            last=now;
            if(G.started&&!G.over&&!G.paused){ game_tick(); broadcast(); }
        }

        Sleep(10);
    }
    WSACleanup(); return 0;
}
