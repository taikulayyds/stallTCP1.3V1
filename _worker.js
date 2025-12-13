import { connect } from 'cloudflare:sockets';

// =============================================================================
// 🟣 用户配置区域 
// =============================================================================
const UUID = "503bc232-238a-50af-8ffa-5a3dc26c6d83"; //支持代码中修改uuid 支持环境变量修改uuid

// 1. 后台管理密码
const WEB_PASSWORD = "taikula666."; //修改你的管理密码
// 2. 快速订阅密码 (访问 https://域名/密码)
const SUB_PASSWORD = ""; //修改你的订阅密码

// 3. 默认基础配置
// 🔴 默认 ProxyIP (代码修改此处生效，客户端修改 path 生效)
const DEFAULT_PROXY_IP = "sjc.o00o.ooo"; //可自定义修改你的proxyip

// 🔴 真实订阅源 (写死读取)
const DEFAULT_SUB_DOMAIN = "sub.cmliussss.net";  //可自定义修改你的sub=优选订阅器

//群组+检测站修改处
const TG_GROUP_URL = "https://t.me/zyssadmin";   
const TG_CHANNEL_URL = "https://t.me/cloudflareorg"; 
const PROXY_CHECK_URL = "https://kaic.hidns.co/"; 

const DEFAULT_CONVERTER = "https://subapi.cmliussss.net"; //可自定义修改你的subapi

// Clash 默认配置 (完整兼容性好)
const CLASH_CONFIG = "https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Full_MultiMode.ini"; //可自定义修改你的订阅配置

// 🚨🚨🚨 [Sing-box 专用配置] 自动双版本容灾 【勿动】
// 优先级 1: 1.12.x
const SINGBOX_CONFIG_V12 = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.json"; //勿动
// 优先级 2: 1.11.x (当 1.12 不可用时自动切换)
const SINGBOX_CONFIG_V11 = "https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.11.x/sing-box.json"; //勿动

// 🔴 TG配置 (在""填写你需要的内容)
const TG_BOT_TOKEN = ""; //你的机器人token
const TG_CHAT_ID = ""; //你的telegram 用户id

const DEFAULT_CUSTOM_IPS = `104.43.91.69#🇸🇬新加坡SG01
34.143.159.175#🇸🇬新加坡SG02
103.210.22.199#🇸🇬新加坡SG03
27.50.48.206#🇸🇬新加坡SG04
34.143.159.175#🇸🇬新加坡SG05
13.250.31.132#🇸🇬新加坡SG06
173.245.58.127#🇺🇸美国US01
173.245.58.201#🇺🇸美国US02
154.21.83.48#🇺🇸美国US03
8.39.125.6#🇺🇸美国US04
74.211.103.172#🇺🇸美国US05
154.21.87.67#🇺🇸美国US06
216.40.87.26#🇺🇸美国US07
154.17.15.98#🇺🇸美国US08
154.21.89.216#🇺🇸美国US09
172.82.16.99#🇺🇸美国US10
142.171.89.242#🇺🇸美国US11
144.34.230.39#🇺🇸美国US12
95.181.189.201#🇺🇸美国US13
173.245.58.201#🇺🇸美国US14
192.9.139.160#🇺🇸美国US15
104.18.33.144#🇺🇸美国US16
198.41.223.138#🇺🇸美国US17
216.167.93.178#🇺🇸美国US18
104.19.37.36#🇺🇸美国US19
108.162.198.41#🇺🇸美国US20
8.39.125.176#🇺🇸美国US21
104.19.61.220#🇺🇸美国US22
104.18.44.31#🇺🇸美国US23
104.19.37.177#🇺🇸美国US24
162.159.38.199#🇺🇸美国US25
8.35.211.134#🇺🇸美国US26
95.40.61.115#🇭🇰香港HK01
8.217.192.104#🇭🇰香港HK02
20.2.112.55#🇭🇰香港HK03
43.161.222.233#🇭🇰香港HK04
58.176.95.46#🇭🇰香港HK05
47.76.218.163#🇭🇰香港HK06
47.242.215.209#🇭🇰香港HK07
103.194.107.166#🇭🇰香港HK08
83.229.126.122#🇭🇰香港HK09
83.229.121.12#🇭🇰香港HK10
47.239.8.172#🇭🇰香港HK11
47.76.218.163#🇭🇰香港HK12
83.229.125.2#🇭🇰香港HK13
149.104.31.162#🇭🇰香港HK14`;

// =============================================================================
// ⚡️ 核心逻辑区
// =============================================================================
const MAX_PENDING=2097152,KEEPALIVE=15000,STALL_TO=8000,MAX_STALL=12,MAX_RECONN=24;
const buildUUID=(a,i)=>[...a.slice(i,i+16)].map(n=>n.toString(16).padStart(2,'0')).join('').replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/,'$1-$2-$3-$4-$5');
const extractAddr=b=>{const o=18+b[17]+1,p=(b[o]<<8)|b[o+1],t=b[o+2];let l,h,O=o+3;switch(t){case 1:l=4;h=b.slice(O,O+l).join('.');break;case 2:l=b[O++];h=new TextDecoder().decode(b.slice(O,O+l));break;case 3:l=16;h=`[${[...Array(8)].map((_,i)=>((b[O+i*2]<<8)|b[O+i*2+1]).toString(16)).join(':')}]`;break;default:throw new Error('Addr type error');}return{host:h,port:p,payload:b.slice(O+l)}};

async function resolveNetlib(n){try{const r=await fetch(`https://1.1.1.1/dns-query?name=${n}&type=TXT`,{headers:{'Accept':'application/dns-json'}});if(!r.ok)return null;const d=await r.json(),t=(d.Answer||[]).filter(x=>x.type===16).map(x=>x.data);if(!t.length)return null;let D=t[0].replace(/^"|"$/g,'');const p=D.replace(/\\010|\n/g,',').split(',').map(s=>s.trim()).filter(Boolean);return p.length?p[Math.floor(Math.random()*p.length)]:null}catch{return null}}
async function parseIP(p){p=p.toLowerCase();if(p.includes('.netlib')){const n=await resolveNetlib(p);p=n||p}let a=p,o=443;if(p.includes('.tp')){const m=p.match(/\.tp(\d+)/);if(m)o=parseInt(m[1],10);return[a,o]}if(p.includes(']:')){const s=p.split(']:');a=s[0]+']';o=parseInt(s[1],10)||o}else if(p.includes(':')&&!p.startsWith('[')){const i=p.lastIndexOf(':');a=p.slice(0,i);o=parseInt(p.slice(i+1),10)||o}return[a,o]}

class Pool{constructor(){this.b=new ArrayBuffer(16384);this.p=0;this.l=[];this.m=8}alloc(s){if(s<=4096&&s<=16384-this.p){const v=new Uint8Array(this.b,this.p,s);this.p+=s;return v}const r=this.l.pop();return r&&r.byteLength>=s?new Uint8Array(r.buffer,0,s):new Uint8Array(s)}free(b){if(b.buffer===this.b)this.p=Math.max(0,this.p-b.length);else if(this.l.length<this.m&&b.byteLength>=1024)this.l.push(b)}reset(){this.p=0;this.l=[]}}

// 🟢 注入功能： 随机打乱排序 + 支持逗号/分号/换行分隔 IP
function genNodes(h,u,p){
    // 使用正则将逗号(,) 分号(;) 替换为换行符，然后按行分割
    // 这样就支持：一行多个IP（逗号隔开），或者多行IP
    let l = DEFAULT_CUSTOM_IPS.replace(/[,;]/g, '\n').split('\n').filter(line => line.trim() !== "");
    
    // 随机打乱
    for (let i = l.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [l[i], l[j]] = [l[j], l[i]];
    }
    const P=p?`/proxyip=${p.trim()}`:"/",E=encodeURIComponent(P);
    const PT='v'+'l'+'e'+'s'+'s';
    return l.map(L=>{
        const[a,n]=L.split('#'),I=a.trim(),N=n?n.trim():'Worker-Node';
        let i=I,pt="443";
        if(I.includes(':')&&!I.includes('[')){const s=I.split(':');i=s[0];pt=s[1]}
        return`${PT}://${u}@${i}:${pt}?encryption=none&security=tls&sni=${h}&alpn=h3&fp=random&allowInsecure=1&type=ws&host=${h}&path=${E}#${encodeURIComponent(N)}`
    }).join('\n');
}

// 🟢 注入功能：TG通知
async function sendTgMsg(ctx, title, r, detail = "") {
  if (!TG_BOT_TOKEN || !TG_CHAT_ID) return;
  try {
    const url = new URL(r.url);
    const ip = r.headers.get('cf-connecting-ip') || 'Unknown';
    const ua = r.headers.get('User-Agent') || 'Unknown';
    const city = r.cf?.city || 'Unknown';
    const time = new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    const safe = (str) => (str || '').replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const text = `<b>📡 ${safe(title)}</b>\n\n` + `<b>🕒 时间:</b> <code>${time}</code>\n` + `<b>🌍 IP:</b> <code>${safe(ip)} (${safe(city)})</code>\n` + `<b>🔗 域名:</b> <code>${safe(url.hostname)}</code>\n` + `<b>🛣️ 路径:</b> <code>${safe(url.pathname)}</code>\n` + `<b>📱 客户端:</b> <code>${safe(ua)}</code>\n` + (detail ? `<b>ℹ️ 详情:</b> ${safe(detail)}` : "");
    const params = { chat_id: TG_CHAT_ID, text: text, parse_mode: 'HTML', disable_web_page_preview: true };
    return fetch(`https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(params) }).catch(e => console.error("TG Send Error:", e));
  } catch(e) { console.error("TG Setup Error:", e); }
}

export default {
  async fetch(r, env, ctx) { 
    try {
      const url = new URL(r.url);
      const host = url.hostname; 
      const UA = (r.headers.get('User-Agent') || "").toLowerCase();

      if (url.pathname === '/favicon.ico') return new Response(null, { status: 404 });

      // 🟢 注入功能：拦截点击 GitHub 链接的通知
      if (url.searchParams.get('flag') === 'github') {
          await sendTgMsg(ctx, "🌟 用户点击了烈火项目", r, "来源: 登录页面直达链接");
          return new Response(null, { status: 204 });
      }

      // =========================================================================
      // 🟢 1. 快速订阅接口 (/:SUB_PASSWORD)
      // =========================================================================
      if (SUB_PASSWORD && url.pathname === `/${SUB_PASSWORD}`) {
          const K_CLASH = 'c'+'l'+'a'+'s'+'h';
          const K_SB = 's'+'i'+'n'+'g'+'-'+'b'+'o'+'x';
          
          const isClash = UA.includes(K_CLASH) || UA.includes('meta') || UA.includes('stash');
          const isSingbox = UA.includes(K_SB) || UA.includes('singbox') || UA.includes('sfi') || UA.includes('box') || UA.includes('karing') || UA.includes('neko');
          const isFlagged = url.searchParams.has('flag');
          const now = Date.now();

          // 🟢 注入功能：订阅通知
          if (!isFlagged) {
             let clientType = "浏览器/未知";
             if (isSingbox) clientType = "Sing-box";
             else if (isClash) clientType = "Clash";
             const p = sendTgMsg(ctx, "订阅被访问/更新", r, `类型: ${clientType}`);
             if(ctx && ctx.waitUntil) ctx.waitUntil(p);
          }

          if (isSingbox && !isFlagged) {
              const requestProxyIp = url.searchParams.get('proxyip');
              let selfUrl = `https://${host}/${SUB_PASSWORD}?flag=true`;
              if (requestProxyIp) selfUrl += `&proxyip=${encodeURIComponent(requestProxyIp)}`;
              
              let targetConfig = SINGBOX_CONFIG_V12;
              try {
                  const controller = new AbortController();
                  const timeoutId = setTimeout(() => controller.abort(), 2000);
                  const checkV12 = await fetch(SINGBOX_CONFIG_V12, { method: 'HEAD', signal: controller.signal });
                  clearTimeout(timeoutId);
                  if (checkV12.status !== 200) targetConfig = SINGBOX_CONFIG_V11;
              } catch (e) { targetConfig = SINGBOX_CONFIG_V11; }

              const converterUrl = `${DEFAULT_CONVERTER}/sub?target=singbox&url=${encodeURIComponent(selfUrl)}&config=${encodeURIComponent(targetConfig)}&emoji=true&list=false&sort=false&fdn=false&scv=false&_t=${now}`;
              const subRes = await fetch(converterUrl);
              const newHeaders = new Headers(subRes.headers);
              newHeaders.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
              newHeaders.set('Pragma', 'no-cache');
              newHeaders.set('Expires', '0');
              return new Response(subRes.body, { status: 200, headers: newHeaders });
          }

          if (isClash && !isFlagged) {
              const requestProxyIp = url.searchParams.get('proxyip');
              let selfUrl = `https://${host}/${SUB_PASSWORD}?flag=true`;
              if (requestProxyIp) selfUrl += `&proxyip=${encodeURIComponent(requestProxyIp)}`;
              const converterUrl = `${DEFAULT_CONVERTER}/sub?target=clash&url=${encodeURIComponent(selfUrl)}&config=${encodeURIComponent(CLASH_CONFIG)}&emoji=true&list=false&tfo=false&scv=false&fdn=false&sort=false&_t=${now}`;
              const subRes = await fetch(converterUrl);
              const newHeaders = new Headers(subRes.headers);
              newHeaders.set('Cache-Control', 'no-store, no-cache, must-revalidate');
              return new Response(subRes.body, { status: 200, headers: newHeaders });
          }

          let upstream = DEFAULT_SUB_DOMAIN.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
          if (!upstream) upstream = host;
          
          let reqProxyIp = url.searchParams.get('proxyip');
          if (!reqProxyIp && DEFAULT_PROXY_IP && DEFAULT_PROXY_IP.trim() !== "") reqProxyIp = DEFAULT_PROXY_IP;

          let targetPath = "/";
          if (reqProxyIp && reqProxyIp.trim() !== "") targetPath = `/proxyip=${reqProxyIp.trim()}`;

          const params = new URLSearchParams();
          params.append("uuid", UUID);
          params.append("host", upstream);
          params.append("sni", upstream);
          params.append("path", targetPath); 
          params.append("type", "ws");
          params.append("encryption", "none");
          params.append("security", "tls");
          params.append("alpn", "h3");
          params.append("fp", "random");
          params.append("allowInsecure", "1");

          const upstreamUrl = `https://${upstream}/sub?${params.toString()}`;

          try {
              const response = await fetch(upstreamUrl, { headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" } });
              if (response.ok) {
                  const text = await response.text();
                  try {
                      let content = atob(text.trim());
                      content = content.replace(/path=[^&#]*/g, `path=${encodeURIComponent(targetPath)}`);
                      content = content.replace(/host=[^&]*/g, `host=${host}`);
                      content = content.replace(/sni=[^&]*/g, `sni=${host}`);
                      return new Response(btoa(content), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
                  } catch (e) { return new Response(text, { status: 200 }); }
              }
          } catch (e) {}
          
          const fallbackList = genNodes(host, UUID, reqProxyIp);
          return new Response(btoa(unescape(encodeURIComponent(fallbackList))), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      // 2. 常规订阅 /sub
      if (url.pathname === '/sub') {
          const requestUUID = url.searchParams.get('uuid');
          if (requestUUID !== UUID) return new Response('Invalid UUID', { status: 403 });
          let pathParam = url.searchParams.get('path');
          let proxyIp = "";
          if (pathParam && pathParam.includes('/proxyip=')) proxyIp = pathParam.split('/proxyip=')[1];
          else if (pathParam === null) proxyIp = DEFAULT_PROXY_IP;
          const listText = genNodes(host, UUID, proxyIp);
          
          // 🟢 注入功能：订阅通知
          const p = sendTgMsg(ctx, "常规订阅访问 (/sub)", r);
          if(ctx && ctx.waitUntil) ctx.waitUntil(p);
          
          return new Response(btoa(unescape(encodeURIComponent(listText))), { status: 200, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
      }

      // 3. 面板逻辑
      if (r.headers.get('Upgrade') !== 'websocket') {
          const noCacheHeaders = {
              'Content-Type': 'text/html; charset=utf-8',
              'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
              'Pragma': 'no-cache',
              'Expires': '0'
          };

          if (WEB_PASSWORD && WEB_PASSWORD.trim().length > 0) {
              const cookie = r.headers.get('Cookie') || "";
              const match = cookie.match(/auth=([^;]+)/);
              const userAuth = match ? match[1] : null;

              if (userAuth !== WEB_PASSWORD) {
                  if (userAuth) {
                      await sendTgMsg(ctx, "🚨 后台登录失败", r, `尝试密码: ${userAuth} (错误)`);
                      return new Response(loginPage(!0), { status: 200, headers: noCacheHeaders });
                  } else {
                      await sendTgMsg(ctx, "👋 后台登录页访问", r, "等待验证");
                      return new Response(loginPage(!1), { status: 200, headers: noCacheHeaders });
                  }
              }
          }
          
          await sendTgMsg(ctx, "✅ 后台登录成功", r, "进入管理面板");
          return new Response(dashPage(url.hostname, UUID), { status: 200, headers: noCacheHeaders });
      }
      
      let proxyIPConfig = null;
      if (url.pathname.includes('/proxyip=')) {
        try {
          const proxyParam = url.pathname.split('/proxyip=')[1].split('/')[0];
          const [address, port] = await parseIP(proxyParam); 
          proxyIPConfig = { address, port: +port }; 
        } catch (e) { console.error(e); }
      }
      const { 0: c, 1: s } = new WebSocketPair(); s.accept(); 
      handle(s, proxyIPConfig); 
      return new Response(null, { status: 101, webSocket: c });
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  }
};

// ⚡️ 核心 WebSocket 逻辑
const handle = (ws, pc) => {
  const pool = new Pool();
  let s, w, r, inf, fst = true, rx = 0, stl = 0, cnt = 0, lact = Date.now(), con = false, rd = false, wt = false, tm = {}, pd = [], pb = 0, scr = 1.0, lck = Date.now(), lrx = 0, md = 'buf', asz = 0, tp = [], st = { t: 0, c: 0, ts: Date.now() };
  const upd = sz => {
    st.t += sz; st.c++; asz = asz * 0.9 + sz * 0.1; const n = Date.now();
    if (n - st.ts > 1000) { const rt = st.t; tp.push(rt); if (tp.length > 5) tp.shift(); st.t = 0; st.ts = n; const av = tp.reduce((a, b) => a + b, 0) / tp.length; if (st.c >= 20) { if (av > 2e7 && asz > 16384) md = 'dir'; else if (av < 1e7 || asz < 8192) md = 'buf'; else md = 'adp' } }
  };
  const rdL = async () => {
    if (rd) return; rd = true; let b = [], bz = 0, tm = null;
    const fl = () => { if (!bz) return; const m = new Uint8Array(bz); let p = 0; for (const x of b) { m.set(x, p); p += x.length } if (ws.readyState === 1) ws.send(m); b = []; bz = 0; if (tm) clearTimeout(tm); tm = null };
    try {
      while (1) {
        if (pb > MAX_PENDING) { await new Promise(r => setTimeout(r, 100)); continue }
        const { done, value: v } = await r.read();
        if (v?.length) {
          rx += v.length; lact = Date.now(); stl = 0; upd(v.length); const n = Date.now();
          if (n - lck > 5000) { const el = n - lck, by = rx - lrx, r = by / el; if (r > 500) scr = Math.min(1, scr + 0.05); else if (r < 50) scr = Math.max(0.1, scr - 0.05); lck = n; lrx = rx }
          if (md === 'buf') { if (v.length < 32768) { b.push(v); bz += v.length; if (bz >= 131072) fl(); else if (!tm) tm = setTimeout(fl, asz > 16384 ? 5 : 20) } else { fl(); if (ws.readyState === 1) ws.send(v) } } else { fl(); if (ws.readyState === 1) ws.send(v) }
        }
        if (done) { fl(); rd = false; rcn(); break }
      }
    } catch { fl(); rd = false; rcn() }
  };
  const wtL = async () => { if (wt) return; wt = true; try { while (wt) { if (!w) { await new Promise(r => setTimeout(r, 100)); continue } if (!pd.length) { await new Promise(r => setTimeout(r, 20)); continue } const b = pd.shift(); await w.write(b); pb -= b.length; pool.free(b) } } catch { wt = false } };
  const est = async () => { try { s = await cn(); w = s.writable.getWriter(); r = s.readable.getReader(); con = false; cnt = 0; scr = Math.min(1, scr + 0.15); lact = Date.now(); rdL(); wtL() } catch { con = false; scr = Math.max(0.1, scr - 0.2); rcn() } };
  const cn = async () => { const m = ['direct']; if (pc) m.push('proxy'); let err; for (const x of m) { try { const o = (x === 'direct') ? { hostname: inf.host, port: inf.port } : { hostname: pc.address, port: pc.port }; const sk = connect(o); await sk.opened; return sk } catch (e) { err = e } } throw err };
  const rcn = async () => { if (!inf || ws.readyState !== 1) { cln(); ws.close(1011); return } if (cnt >= MAX_RECONN) { cln(); ws.close(1011); return } if (con) return; cnt++; let d = Math.min(50 * Math.pow(1.5, cnt - 1), 3000) * (1.5 - scr * 0.5); d = Math.max(50, Math.floor(d)); try { csk(); if (pb > MAX_PENDING * 2) while (pb > MAX_PENDING && pd.length > 5) { const k = pd.shift(); pb -= k.length; pool.free(k) } await new Promise(r => setTimeout(r, d)); con = true; s = await cn(); w = s.writable.getWriter(); r = s.readable.getReader(); con = false; cnt = 0; scr = Math.min(1, scr + 0.15); stl = 0; lact = Date.now(); rdL(); wtL() } catch { con = false; scr = Math.max(0.1, scr - 0.2); if (cnt < MAX_RECONN && ws.readyState === 1) setTimeout(rcn, 500); else { cln(); ws.close(1011) } } };
  const stT = () => { tm.ka = setInterval(async () => { if (!con && w && Date.now() - lact > KEEPALIVE) try { await w.write(new Uint8Array(0)); lact = Date.now() } catch { rcn() } }, 5000); tm.hc = setInterval(() => { if (!con && st.t > 0 && Date.now() - lact > STALL_TO) { stl++; if (stl >= MAX_STALL) { if (cnt < MAX_RECONN) { stl = 0; rcn() } else { cln(); ws.close(1011) } } } }, 4000) };
  const csk = () => { rd = false; wt = false; try { w?.releaseLock(); r?.releaseLock(); s?.close() } catch { } }; const cln = () => { Object.values(tm).forEach(clearInterval); csk(); while (pd.length) pool.free(pd.shift()); pb = 0; st = { t: 0, c: 0, ts: Date.now() }; md = 'buf'; asz = 0; tp = []; pool.reset() };
  ws.addEventListener('message', async e => { try { if (fst) { fst = false; const b = new Uint8Array(e.data); if (buildUUID(b, 1).toLowerCase() !== UUID.toLowerCase()) throw 0; ws.send(new Uint8Array([0, 0])); const { host, port, payload } = extractAddr(b); inf = { host, port }; con = true; if (payload.length) { const z = pool.alloc(payload.length); z.set(payload); pd.push(z); pb += z.length } stT(); est() } else { lact = Date.now(); if (pb > MAX_PENDING * 2) return; const z = pool.alloc(e.data.byteLength); z.set(new Uint8Array(e.data)); pd.push(z); pb += z.length } } catch { cln(); ws.close(1006) } }); ws.addEventListener('close', cln); ws.addEventListener('error', cln)
};

// UI 代码压缩 (已更新红色文字、Placeholder和烈火项目)
function loginPage(e){return`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Worker Login</title><style>body{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:white;font-family:'Segoe UI',sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.glass-box{background:rgba(255,255,255,0.1);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,0.2);padding:40px;border-radius:16px;box-shadow:0 8px 32px 0 rgba(31,38,135,0.37);text-align:center;width:320px}h2{margin-top:0;margin-bottom:20px;font-weight:600;letter-spacing:1px}input{width:100%;padding:14px;margin-bottom:20px;border-radius:8px;border:1px solid rgba(255,255,255,0.3);background:rgba(0,0,0,0.2);color:white;box-sizing:border-box;text-align:center;font-size:1rem;outline:none;transition:0.3s}input:focus{background:rgba(0,0,0,0.4);border-color:#a29bfe}button{width:100%;padding:12px;border-radius:8px;border:none;background:linear-gradient(90deg,#a29bfe,#6c5ce7);color:white;font-weight:bold;cursor:pointer;font-size:1rem;box-shadow:0 4px 15px rgba(0,0,0,0.2);transition:0.2s}button:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,0.3)}.social-links{margin-top:25px;display:flex;justify-content:center;gap:15px;border-top:1px solid rgba(255,255,255,0.1);padding-top:20px;flex-wrap:wrap}.social-links a{color:#e2e8f0;text-decoration:none;font-size:0.9rem;padding:8px 16px;background:rgba(0,0,0,0.2);border-radius:20px;border:1px solid rgba(255,255,255,0.15);transition:0.2s;display:flex;align-items:center;gap:5px}.social-links a:hover{background:rgba(255,255,255,0.2);transform:translateY(-2px);border-color:#a29bfe}.error-msg{background:rgba(231,76,60,0.3);border:1px solid rgba(231,76,60,0.5);color:#ff7675;padding:10px;border-radius:8px;margin-bottom:15px;font-size:0.9rem;display:${e?"block":"none"}}</style></head><body><div class="glass-box"><h2>🔒 禁止进入</h2><div class="error-msg">⚠️ 密码错误，请重试</div><input type="password" id="pwd" placeholder="请输入密码" autofocus onkeypress="if(event.keyCode===13)verify()"><button onclick="verify()">解锁后台</button><div class="social-links"><a href="javascript:void(0)" onclick="gh()">🔥 烈火项目直达</a><a href="${TG_CHANNEL_URL}" target="_blank">📢 天诚频道组</a><a href="${TG_GROUP_URL}" target="_blank">✈️ 天诚交流群</a></div></div><script>function gh(){fetch("?flag=github&t="+Date.now(),{keepalive:!0});window.open("https://github.com/xtgm/stallTCP1.3V1","_blank")}function verify(){const p=document.getElementById("pwd").value,d=new Date;d.setTime(d.getTime()+6048e5),document.cookie="auth="+p+";expires="+d.toUTCString()+";path=/",location.reload()}<\/script></body></html>`}
function dashPage(e,t){const s=TG_BOT_TOKEN&&TG_CHAT_ID?'<div class="status-item available">🤖 Telegram 通知: <span style="color:#00b894;font-weight:bold">已开启</span></div>':'<div class="status-item">🤖 Telegram 通知: <span style="color:#fab1a0">未配置</span></div>';return`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Worker 订阅管理</title><style>:root{--glass:rgba(255,255,255,0.1);--border:rgba(255,255,255,0.2)}body{background:linear-gradient(135deg,#2b1055 0%,#7597de 100%);color:white;font-family:'Segoe UI',system-ui,sans-serif;margin:0;padding:20px;min-height:100vh;display:flex;justify-content:center;box-sizing:border-box}.container{max-width:800px;width:100%}.card{background:var(--glass);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid var(--border);border-radius:16px;padding:25px;margin-bottom:20px;box-shadow:0 8px 32px 0 rgba(0,0,0,0.3)}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;padding-bottom:15px;border-bottom:1px solid var(--border)}h1{margin:0;font-size:1.5rem;font-weight:600;text-shadow:0 2px 4px rgba(0,0,0,0.3)}h3{margin-top:0;font-size:1.1rem;border-bottom:1px solid var(--border);padding-bottom:10px;color:#dfe6e9}.btn-group{display:flex;gap:10px}.btn-small{font-size:.85rem;cursor:pointer;background:rgba(0,0,0,0.3);padding:5px 12px;border-radius:6px;text-decoration:none;color:white;transition:.2s;border:1px solid transparent}.btn-small:hover{background:rgba(255,255,255,0.2);border-color:rgba(255,255,255,0.5)}.field{margin-bottom:18px}.label{display:block;font-size:.9rem;color:#dfe6e9;margin-bottom:8px;font-weight:500}.input-group{display:flex;gap:10px}input,textarea{width:100%;background:rgba(0,0,0,0.25);border:1px solid var(--border);color:white;padding:12px;border-radius:8px;font-family:monospace;outline:none;transition:.2s;box-sizing:border-box}input:focus,textarea:focus{background:rgba(0,0,0,0.4);border-color:#a29bfe}textarea{min-height:120px;resize:vertical;line-height:1.4}button.main-btn{background:linear-gradient(90deg,#6c5ce7,#a29bfe);color:white;border:none;padding:12px 20px;border-radius:8px;cursor:pointer;font-weight:600;width:100%;margin-top:5px;transition:.2s;box-shadow:0 4px 6px rgba(0,0,0,0.2);font-size:1rem}button.main-btn:hover{transform:translateY(-2px);opacity:.95}button.sec-btn{background:rgba(255,255,255,0.15);color:white;border:1px solid var(--border);padding:12px;border-radius:8px;cursor:pointer;white-space:nowrap;transition:.2s}button.sec-btn:hover{background:rgba(255,255,255,0.3)}.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%);background:#00b894;color:white;padding:10px 24px;border-radius:30px;opacity:0;transition:.3s;pointer-events:none;box-shadow:0 5px 15px rgba(0,0,0,0.3);font-weight:bold}.toast.show{opacity:1;bottom:50px}.desc{font-size:.8rem;color:#b2bec3;margin-top:6px}.checkbox-wrapper{display:flex;align-items:center;margin-top:10px;background:rgba(0,0,0,0.2);padding:8px 12px;border-radius:6px;width:fit-content}.checkbox-wrapper input{width:auto;margin-right:8px;cursor:pointer}.checkbox-wrapper label{cursor:pointer;font-size:.9rem;color:#dfe6e9}.status-item{background:rgba(0,0,0,0.2);padding:8px 12px;border-radius:6px;font-size:.9rem;margin-top:10px;display:inline-block}</style></head><body><div class="container"><div class="card"><div class="header"><h1>⚡ Worker 管理面板</h1><div class="btn-group"><a href="${TG_GROUP_URL}" target="_blank" class="btn-small">✈️ 加入群组</a><span class="btn-small" onclick="logout()">退出登录</span></div></div><div style="margin-bottom:20px;text-align:center">${s}</div><div class="field" style="background:rgba(108,92,231,0.2);padding:15px;border-radius:10px;border:1px solid rgba(162,155,254,0.4)"><span class="label" style="color:#a29bfe;font-weight:bold">🚀 快速自适应订阅 (推荐) 通用订阅复制这里</span><div class="input-group"><input type="text" id="shortSub" value="https://${e}/${SUB_PASSWORD}" readonly onclick="this.select()"><button class="sec-btn" onclick="copyId('shortSub')">复制</button></div><div class="desc">直接使用此链接。支持通用订阅客户端(自适应客户端订阅)。<br/>节点将自动抓取上游并替换为Worker加速。</div><div style="margin-top:10px;font-size:0.9rem;color:#ff4757;font-weight:bold;text-align:center;">【↓下方的可修改内容指向手动订阅链接】</div></div><div class="field"><span class="label">1. 订阅数据源 (Sub优选订阅器处)</span><input type="text" id="subBaseUrl" value="https://${e}" placeholder="https://你的sub地址或者是worker域名地址" oninput="updateLink()"><div class="desc">这里可修改成你的sub地址或者是你的worker域名地址。</div></div><div class="field"><span class="label">2.Proxyip修改处 (ProxyIP)</span><div class="input-group"><input type="text" id="proxyIp" value="${DEFAULT_PROXY_IP}" placeholder="例如: 你的proxyip地址" oninput="updateLink()"><button class="sec-btn" onclick="checkProxy()">🔍 检测</button></div><div class="desc">这里决定了你的proxyip地址，谨慎修改正确的proxyip地址内容。</div></div><div class="field" id="clashSettings" style="display:none;background:rgba(0,0,0,0.15);padding:15px;border-radius:8px;margin-bottom:18px;border:1px dashed #6c5ce7"><span class="label" style="color:#a29bfe">⚙️ Clash 高级配置</span><div style="margin-bottom:10px"><span class="label" style="font-size:0.85rem">转换后端:</span><input type="text" id="converterUrl" value="${DEFAULT_CONVERTER}" oninput="updateLink()"></div><div><span class="label" style="font-size:0.85rem">远程配置:</span><input type="text" id="configUrl" value="https://raw.githubusercontent.com/sinspired/sub-store-template/main/1.12.x/sing-box.json" oninput="updateLink()"></div></div><div class="field"><span class="label">3. 手动生成订阅链接 (Legacy)</span><input type="text" id="resultUrl" readonly onclick="this.select()"><div class="checkbox-wrapper"><input type="checkbox" id="clashMode" onchange="toggleClashMode()"><label for="clashMode">🔄 开启 Clash 转换</label></div></div><div class="input-group"><button class="main-btn" onclick="copyId('resultUrl')">📄 复制订阅链接</button><button class="sec-btn" onclick="window.open(document.getElementById('resultUrl').value)" style="width:120px">🚀 测试</button></div></div><div class="card"><h3>🚀 优选IP预览</h3><div class="field"><span class="label">内置 IP 列表</span><textarea id="customIps" readonly style="background:rgba(0,0,0,0.2);border-color:transparent;cursor:default;height:150px">${DEFAULT_CUSTOM_IPS}</textarea></div></div></div><div id="toast" class="toast">已复制!</div><script>function toggleClashMode(){const e=document.getElementById("clashMode").checked;document.getElementById("clashSettings").style.display=e?"block":"none",updateLink()}function updateLink(){let e=document.getElementById("subBaseUrl").value.trim();e.endsWith("/")&&(e=e.slice(0,-1)),e.startsWith("http")||(e="https://"+e);const t=document.getElementById("proxyIp").value.trim(),s="${t}",n=document.getElementById("clashMode").checked;let r="/";t&&(r="/proxyip="+t);const o=e+"/sub?uuid="+s+"&path="+encodeURIComponent(r);if(n){let e=document.getElementById("converterUrl").value.trim();e.endsWith("/")&&(e=e.slice(0,-1));const t=document.getElementById("configUrl").value.trim();let s=t?"&config="+encodeURIComponent(t):"";document.getElementById("resultUrl").value=e+"/sub?target=clash&url="+encodeURIComponent(o)+s+"&emoji=true&list=false&tfo=false&scv=false&fdn=false&sort=false"}else document.getElementById("resultUrl").value=o}function copyId(e){navigator.clipboard.writeText(document.getElementById(e).value).then((()=>showToast("已复制!")))}function checkProxy(){const e=document.getElementById("proxyIp").value.trim();fetch("?flag=checkproxy&ip="+encodeURIComponent(e)+"&t="+Date.now(),{keepalive:!0});e?(navigator.clipboard.writeText(e).then((()=>{alert("ProxyIP 已复制!"),window.open("${PROXY_CHECK_URL}","_blank")}))):window.open("${PROXY_CHECK_URL}","_blank")}function showToast(e){const t=document.getElementById("toast");t.innerText=e,t.classList.add("show"),setTimeout((()=>t.classList.remove("show")),2e3)}function logout(){document.cookie="auth=;expires=Thu,01 Jan 1970 00:00:00 UTC;path=/;",location.reload()}window.onload=()=>{updateLink()};<\/script></body></html>`}