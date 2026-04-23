import express from 'express';
import { randomBytes, createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { resolve } from 'path';
import { config } from './config.js';
import * as db from './db.js';

const app = express();
const { delayMs } = config.deception;

// 無狀態 session：HMAC 簽名 cookie 追蹤登入嘗試次數
const LOGIN_SIGN_SECRET = randomBytes(32).toString('hex');
const FAIL_BEFORE_SUCCESS = 2;

app.set('trust proxy', true);
app.use(express.raw({ type: () => true, limit: '8kb' }));

// ── Helpers ──────────────────────────────────────────────────────────────────

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    const first = String(forwarded).split(',')[0].trim();
    if (first) return first;
  }
  const realIp = req.headers['x-real-ip'];
  if (realIp) return String(realIp).trim();
  return req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || '';
}

function applyFakeHeaders(res, options = {}) {
  const sessionId = randomBytes(16).toString('hex');
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  res.setHeader('X-Powered-By', 'PHP/7.4.3');
  res.setHeader('Date', new Date().toUTCString());
  res.setHeader('Set-Cookie', `PHPSESSID=${sessionId}; path=/; HttpOnly`);
  if (options.cache) {
    res.setHeader('Cache-Control', 'max-age=3600, public');
    res.setHeader('ETag', `"${randomBytes(8).toString('hex')}"`);
  } else {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
  }
}

function signSession(count, ip) {
  const payload = `${count}:${ip}`;
  const sig = createHash('sha256').update(payload + LOGIN_SIGN_SECRET).digest('hex').slice(0, 16);
  return `${count}.${sig}`;
}

function readSession(cookieVal, ip) {
  if (!cookieVal) return 0;
  const [countStr, sig] = cookieVal.split('.');
  const count = parseInt(countStr, 10) || 0;
  const expected = createHash('sha256').update(`${count}:${ip}` + LOGIN_SIGN_SECRET).digest('hex').slice(0, 16);
  if (sig !== expected) return 0;
  return count;
}

function parseCookie(str, name) {
  const match = (str || '').match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

function parseFormBody(buf) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return {};
  try { return Object.fromEntries(new URLSearchParams(buf.toString('utf8'))); } catch (_) { return {}; }
}

// ── Fake Content ──────────────────────────────────────────────────────────────

function fakePasswd() {
  return `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:109:114:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
usbmux:x:110:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:111:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:999:999:MySQL Server,,,:/var/lib/mysql:/bin/false
edu-admin:x:1001:1001:Education System Admin,,,:/home/edu-admin:/bin/bash
backup-svc:x:1002:1002:Backup Service,,,:/home/backup-svc:/bin/bash
`;
}

function fakeShell(req) {
  const raw = ((req.url || '') + (req.body && Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '')).toLowerCase();

  if (/cat\s+\/etc\/passwd/.test(raw)) return fakePasswd();
  if (/cat\s+\/etc\/shadow/.test(raw)) return 'cat: /etc/shadow: Permission denied\n';
  if (/cat\s+config\.php/.test(raw) || /cat\s+.*\.php/.test(raw)) {
    return `<?php
define('DB_HOST', 'edu-db-01.guanghua.edu.tw');
define('DB_NAME', 'ghshs_portal');
define('DB_USER', 'ghshs_app');
define('DB_PASSWORD', 'Gh$hs_Pr0d_2024!');
define('APP_ENV', 'production');
define('APP_SECRET', 'b3f9a2c7e1d4f6a8b2c5e7f9a1d3b5c7');
?>\n`;
  }
  if (/\bls\b/.test(raw)) {
    return `total 72
drwxr-xr-x 6 www-data www-data 4096 Mar 14 08:22 .
drwxr-xr-x 4 root     root     4096 Jan  5 09:00 ..
-rw-r--r-- 1 www-data www-data  512 Feb 20 10:15 .htaccess
-rw-r--r-- 1 www-data www-data 8192 Mar 14 08:22 config.php
drwxr-xr-x 3 www-data www-data 4096 Feb 20 10:15 admin
-rw-r--r-- 1 www-data www-data 2048 Mar 10 14:33 index.php
-rw-r--r-- 1 www-data www-data 4096 Mar 12 09:17 login.php
drwxr-xr-x 2 www-data www-data 4096 Mar  1 11:00 student
drwxr-xr-x 2 www-data www-data 4096 Mar  1 11:00 teacher
drwxr-xr-x 2 www-data www-data 4096 Jan 10 08:00 uploads
`;
  }
  if (/\bpwd\b/.test(raw)) return '/var/www/html/ghshs\n';
  if (/\bwhoami\b/.test(raw)) return 'www-data\n';
  if (/\bid\b/.test(raw)) return 'uid=33(www-data) gid=33(www-data) groups=33(www-data)\n';
  if (/uname/.test(raw)) return 'Linux edu-web-01 5.4.0-169-generic #187-Ubuntu SMP Thu Jan 4 13:02:26 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n';
  if (/hostname/.test(raw)) return 'edu-web-01.guanghua.edu.tw\n';
  if (/ifconfig|ip\s+addr|ip\s+a\b/.test(raw)) {
    return `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.100.1.15  netmask 255.255.255.0  broadcast 10.100.1.255
        inet6 fe80::216:3eff:fe00:1  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:00:00:01  txqueuelen 1000  (Ethernet)
        RX packets 4872341  bytes 1823456789 (1.8 GB)
        TX packets 3912084  bytes 892345678 (892.3 MB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
`;
  }
  if (/ps\s+aux|ps\s+-ef/.test(raw)) {
    return `USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1   8936  5432 ?        Ss   Jan05   0:12 /sbin/init
root       423  0.0  0.2  72356  9876 ?        Ss   Jan05   0:00 /usr/sbin/sshd -D
root       789  0.0  0.1  14524  6432 ?        Ss   Jan05   0:01 cron
mysql      891  0.3  5.2 1823456 213456 ?      Sl   Jan05  14:22 /usr/sbin/mysqld
root      1024  0.0  0.3  89432 12345 ?        Ss   Jan05   0:00 /usr/sbin/apache2 -k start
www-data  1025  0.1  0.8  98765 34567 ?        S    Jan05   2:31 /usr/sbin/apache2 -k start
www-data  1026  0.1  0.8  98765 34567 ?        S    Jan05   2:30 /usr/sbin/apache2 -k start
www-data  1027  0.0  0.6  92345 25678 ?        S    Jan05   1:15 php-fpm7.4: pool www
root      2048  0.0  0.1  14512  4320 ?        Ss   02:00   0:00 python3 /opt/scripts/backup.py
`;
  }
  if (/netstat|ss\s+-/.test(raw)) {
    return `Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN
tcp6       0      0 :::22                   :::*                    LISTEN
tcp6       0      0 :::80                   :::*                    LISTEN
`;
  }
  if (/\benv\b|\bprintenv\b/.test(raw)) {
    return `SHELL=/bin/bash
USER=www-data
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOME=/var/www
PWD=/var/www/html/ghshs
PHP_VERSION=7.4.3
DB_HOST=edu-db-01.guanghua.edu.tw
DB_NAME=ghshs_portal
DB_USER=ghshs_app
DB_PASS=Gh$hs_D3v_2024!
APP_ENV=production
`;
  }
  if (/wget|curl\s/.test(raw)) {
    return `--2024-03-14 09:22:11--  http://...
Resolving ... (...)... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4096 (4.0K) [application/octet-stream]
Saving to: 'output'
output              100%[===================>]   4.00K  --.-KB/s    in 0s
2024-03-14 09:22:11 (--.-KB/s) - 'output' saved [4096/4096]
`;
  }
  if (/python3?/.test(raw)) return 'Python 3.8.10 (default, Nov 14 2022, 12:59:47)\n[GCC 9.4.0] on linux\nType "help", "copyright", "credits" or "license" for more information.\n';

  const cmdMatch = raw.match(/(?:cmd|command|exec|run)=([^&\s]+)/);
  const cmd = cmdMatch ? cmdMatch[1] : raw.slice(-30).trim();
  return `bash: ${cmd}: command not found\n`;
}

function fakePhpInfo() {
  return `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif; font-size: 12px;}
td, th {border: 1px solid #666; font-size: 12px; vertical-align: baseline; padding: 3px 5px;}
h1 {font-size: 150%;}
h2 {font-size: 125%;}
.e {background-color: #ccf; width: 300px; font-weight: bold;}
.h {background-color: #99e; font-weight: bold;}
.v {background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}
.vr {background-color: #ddd; text-align: right;}
hr {width: 600px; background-color: #ccf; border: 0; height: 1px;}
</style>
<title>phpinfo()</title>
</head>
<body>
<div class="center">
<table border="0" cellpadding="3" width="600">
<tr class="h"><td>
<h1 class="p">PHP Version 7.4.3</h1>
</td></tr>
</table>
<br />
<table border="0" cellpadding="3" width="600">
<tr><td class="e">System</td><td class="v">Linux edu-web-01 5.4.0-169-generic #187-Ubuntu SMP Thu Jan 4 13:02:26 UTC 2024 x86_64</td></tr>
<tr><td class="e">Build Date</td><td class="v">Jan  5 2024 14:22:15</td></tr>
<tr><td class="e">Server API</td><td class="v">FPM/FastCGI</td></tr>
<tr><td class="e">Virtual Directory Support</td><td class="v">disabled</td></tr>
<tr><td class="e">Configuration File (php.ini) Path</td><td class="v">/etc/php/7.4/fpm</td></tr>
<tr><td class="e">Loaded Configuration File</td><td class="v">/etc/php/7.4/fpm/php.ini</td></tr>
<tr><td class="e">PHP API</td><td class="v">20190902</td></tr>
<tr><td class="e">PHP Extension</td><td class="v">20190902</td></tr>
<tr><td class="e">Zend Extension</td><td class="v">320190902</td></tr>
</table>
<h2>Configuration</h2>
<h2><a name="module_core">Core</a></h2>
<table border="0" cellpadding="3" width="600">
<tr class="h"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>
<tr><td class="e">allow_url_fopen</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">allow_url_include</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">always_populate_raw_post_data</td><td class="v">-1</td><td class="v">-1</td></tr>
<tr><td class="e">disable_functions</td><td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait</td><td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait</td></tr>
<tr><td class="e">display_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">display_startup_errors</td><td class="v">Off</td><td class="v">Off</td></tr>
<tr><td class="e">error_reporting</td><td class="v">32767</td><td class="v">32767</td></tr>
<tr><td class="e">file_uploads</td><td class="v">On</td><td class="v">On</td></tr>
<tr><td class="e">max_execution_time</td><td class="v">30</td><td class="v">30</td></tr>
<tr><td class="e">max_file_uploads</td><td class="v">20</td><td class="v">20</td></tr>
<tr><td class="e">max_input_time</td><td class="v">60</td><td class="v">60</td></tr>
<tr><td class="e">memory_limit</td><td class="v">128M</td><td class="v">128M</td></tr>
<tr><td class="e">open_basedir</td><td class="v">/var/www/html:/var/www/ghshs:/tmp:/var/lib/php</td><td class="v">/var/www/html:/var/www/ghshs:/tmp:/var/lib/php</td></tr>
<tr><td class="e">post_max_size</td><td class="v">8M</td><td class="v">8M</td></tr>
<tr><td class="e">session.save_handler</td><td class="v">files</td><td class="v">files</td></tr>
<tr><td class="e">session.save_path</td><td class="v">/var/lib/php/sessions</td><td class="v">/var/lib/php/sessions</td></tr>
<tr><td class="e">upload_max_filesize</td><td class="v">2M</td><td class="v">2M</td></tr>
<tr><td class="e">upload_tmp_dir</td><td class="v">/tmp</td><td class="v">/tmp</td></tr>
<tr><td class="e">variables_order</td><td class="v">GPCS</td><td class="v">GPCS</td></tr>
</table>
<h2><a name="module_pdo_mysql">PDO Driver for MySQL</a></h2>
<table border="0" cellpadding="3" width="600">
<tr class="h"><th>PDO Driver for MySQL</th><th></th></tr>
<tr><td class="e">Client API version</td><td class="v">mysqlnd 7.4.3</td></tr>
</table>
<h2><a name="module_curl">curl</a></h2>
<table border="0" cellpadding="3" width="600">
<tr class="h"><th>curl</th><th></th></tr>
<tr><td class="e">cURL Information</td><td class="v">7.68.0</td></tr>
<tr><td class="e">Age</td><td class="v">9</td></tr>
<tr><td class="e">Features</td><td class="v">IPv6, Largefile, NTLM, SSL (OpenSSL/1.1.1f)</td></tr>
<tr><td class="e">Host</td><td class="v">x86_64-pc-linux-gnu</td></tr>
</table>
<h2><a name="module_mbstring">mbstring</a></h2>
<table border="0" cellpadding="3" width="600">
<tr class="h"><th>mbstring</th><th></th></tr>
<tr><td class="e">Multibyte Support</td><td class="v">enabled</td></tr>
<tr><td class="e">Multibyte string engine</td><td class="v">libmbfl</td></tr>
<tr><td class="e">HTTP input encoding translation</td><td class="v">disabled</td></tr>
<tr><td class="e">mbstring.internal_encoding</td><td class="v">UTF-8</td></tr>
<tr><td class="e">mbstring.http_input</td><td class="v">pass</td></tr>
<tr><td class="e">mbstring.http_output</td><td class="v">pass</td></tr>
<tr><td class="e">mbstring.detect_order</td><td class="v">auto</td></tr>
</table>
<h2><a name="module_openssl">openssl</a></h2>
<table border="0" cellpadding="3" width="600">
<tr class="h"><th>openssl</th><th></th></tr>
<tr><td class="e">OpenSSL support</td><td class="v">enabled</td></tr>
<tr><td class="e">OpenSSL Library Version</td><td class="v">OpenSSL 1.1.1f  31 Mar 2020</td></tr>
<tr><td class="e">OpenSSL Header Version</td><td class="v">OpenSSL 1.1.1f  31 Mar 2020</td></tr>
</table>
</div>
</body>
</html>`;
}

function fakeSql() {
  return JSON.stringify({
    query: 'SELECT * FROM students LIMIT 5',
    rows: [
      { id: 1, student_id: 'S110001', name: '王大明', class: '高一甲', email: 's110001@guanghua.edu.tw', password_hash: '$2y$10$KIXhfuJMLnzX9PLtS2vIJuGAh5wMPPkRQGWX/FtklSd1cjRnBaRnW', created_at: '2023-09-01 08:00:00' },
      { id: 2, student_id: 'S110002', name: '李小華', class: '高一甲', email: 's110002@guanghua.edu.tw', password_hash: '$2y$10$3IzMeW9fJDqnEFVLxH7ZBuPyX1M2kaIREhCxFEpBt3uNdcBvSjPzO', created_at: '2023-09-01 08:01:00' },
      { id: 3, student_id: 'S110042', name: '張雅婷', class: '高一乙', email: 's110042@guanghua.edu.tw', password_hash: '$2y$10$9LmI4RwJQhFT7DxKNoBVRuQ8bY2kFZ6vSGMp3jAEcWnXdO1yTstDk', created_at: '2023-09-01 08:02:00' },
      { id: 4, student_id: 'T00312',  name: '陳志明', class: null,    email: 't00312@guanghua.edu.tw',  password_hash: '$2y$10$pXJT5MoH2REkZsC9BvWhSe7GnYI1lQwMjK4uFrAb6Dc3NVgtXOvLs', created_at: '2022-08-01 09:00:00' },
      { id: 5, student_id: 'T00156',  name: '林美玲', class: null,    email: 't00156@guanghua.edu.tw',  password_hash: '$2y$10$hHxEJ1Lm9Pu8Mty7RsWQuZN6bI5sDXkvFYcpTjObC2QrAn0KgVwIe', created_at: '2021-08-01 09:00:00' },
    ],
  });
}

function fakeJndi() {
  return `log4j:ERROR Error executing JNDI lookup
\tat com.sun.jndi.ldap.LdapCtx.processReturnCode(LdapCtx.java:1761)
\tat com.sun.jndi.ldap.LdapCtx.processReturnCode(LdapCtx.java:1742)
Caused by: javax.naming.PartialResultException: [LDAP: error code 10 - 0000202B: RefErr: DSID-031007F8]
Connected to: ldap://remote-host:1389/Exploit
javax.naming.directory.InitialDirContext: lookup completed
\tat com.sun.jndi.ldap.LdapClient.authenticate(LdapClient.java:252)
`;
}

function fakeApi(req) {
  const path = req.path || '';
  if (/\/users/.test(path)) {
    return JSON.stringify({
      status: 'ok', version: '2.1.4',
      timestamp: new Date().toISOString(),
      data: [
        { id: 1, username: 'edu-admin', role: 'administrator', email: 'edu-admin@guanghua.edu.tw' },
        { id: 2, username: 'backup-svc', role: 'service', email: 'backup@guanghua.edu.tw' },
      ],
    });
  }
  return JSON.stringify({
    status: 'error',
    version: '2.1.4',
    timestamp: new Date().toISOString(),
    data: { message: 'Unauthorized', code: 401 },
    request_id: randomBytes(4).toString('hex'),
  });
}

// ── HTML Pages ────────────────────────────────────────────────────────────────

function pageLogin(errorMsg = '') {
  const token = randomBytes(16).toString('hex');
  const errorHtml = errorMsg
    ? `<div class="alert">${errorMsg}</div>`
    : '';
  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>光華校務系統 - 登入</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Microsoft JhengHei","PingFang TC",sans-serif;background:linear-gradient(135deg,#1a3a5c 0%,#1a5f9e 60%,#2980b9 100%);min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center}
.logo-wrap{text-align:center;margin-bottom:24px;color:#fff}
.logo-circle{width:72px;height:72px;border-radius:50%;background:#fff;display:inline-flex;align-items:center;justify-content:center;margin-bottom:12px}
.logo-circle svg{width:44px;height:44px}
.logo-wrap h1{font-size:22px;font-weight:700;letter-spacing:1px}
.logo-wrap p{font-size:13px;opacity:.85;margin-top:4px}
.card{background:#fff;border-radius:8px;box-shadow:0 8px 32px rgba(0,0,0,.25);padding:36px 40px;width:100%;max-width:400px}
.card h2{font-size:16px;color:#333;margin-bottom:20px;text-align:center;font-weight:600}
.alert{background:#fdf0f0;border:1px solid #e74c3c;color:#c0392b;padding:10px 14px;border-radius:4px;font-size:13px;margin-bottom:16px}
label{display:block;font-size:13px;color:#555;margin-bottom:5px;font-weight:500}
input[type=text],input[type=password]{width:100%;border:1px solid #ccc;border-radius:4px;padding:9px 12px;font-size:14px;outline:none;transition:border .2s}
input[type=text]:focus,input[type=password]:focus{border-color:#1a5f9e}
.form-group{margin-bottom:16px}
.checkbox-row{display:flex;align-items:center;gap:8px;margin-bottom:20px;font-size:13px;color:#666}
.btn-submit{width:100%;background:#1a5f9e;color:#fff;border:none;border-radius:4px;padding:10px;font-size:15px;font-weight:600;cursor:pointer;letter-spacing:1px;transition:background .2s}
.btn-submit:hover{background:#145286}
.forgot{display:block;text-align:center;margin-top:14px;font-size:12px;color:#888}
.footer{margin-top:28px;text-align:center;color:rgba(255,255,255,.6);font-size:11px}
</style>
</head>
<body>
<div class="logo-wrap">
  <div class="logo-circle">
    <svg viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
      <circle cx="22" cy="22" r="20" stroke="#1a5f9e" stroke-width="2.5"/>
      <path d="M10 28 L22 14 L34 28" stroke="#1a5f9e" stroke-width="2.5" stroke-linejoin="round" fill="none"/>
      <rect x="17" y="22" width="10" height="8" rx="1" fill="#1a5f9e"/>
    </svg>
  </div>
  <h1>台北市立光華高中</h1>
  <p>教職員及學生校務系統</p>
</div>
<div class="card">
  <h2>登入校務系統</h2>
  ${errorHtml}
  <form method="POST" action="/login">
    <input type="hidden" name="_token" value="${token}">
    <div class="form-group">
      <label for="username">學號 / 工號</label>
      <input type="text" id="username" name="username" placeholder="請輸入學號或工號" autocomplete="username" required>
    </div>
    <div class="form-group">
      <label for="password">密碼</label>
      <input type="password" id="password" name="password" placeholder="請輸入密碼" autocomplete="current-password" required>
    </div>
    <div class="checkbox-row">
      <input type="checkbox" id="remember" name="remember" value="1">
      <label for="remember" style="margin:0">記住我的登入狀態</label>
    </div>
    <button type="submit" class="btn-submit">登入系統</button>
  </form>
  <a href="#" class="forgot">忘記密碼？請洽教務處分機 201</a>
</div>
<div class="footer">台北市立光華高中 資訊組 &copy; 2024 | 光華校務系統 v3.2.1</div>
<!-- GHSHS-Portal v3.2.1 build:2024-02-20 PHP/7.4.3 -->
</body>
</html>`;
}

function pagePortal() {
  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>光華校務系統 - 學務管理</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Microsoft JhengHei","PingFang TC",sans-serif;background:#f0f2f5;min-height:100vh;display:flex}
.sidebar{width:220px;background:#1a3a5c;color:#fff;display:flex;flex-direction:column;min-height:100vh;flex-shrink:0}
.sidebar-header{padding:20px 16px 16px;border-bottom:1px solid rgba(255,255,255,.1)}
.sidebar-header h2{font-size:14px;font-weight:700;letter-spacing:1px}
.sidebar-header p{font-size:11px;opacity:.6;margin-top:3px}
.sidebar-nav{flex:1;padding:12px 0}
.sidebar-nav a{display:block;padding:10px 20px;font-size:13px;color:rgba(255,255,255,.8);text-decoration:none;transition:background .15s}
.sidebar-nav a:hover,.sidebar-nav a.active{background:rgba(255,255,255,.12);color:#fff}
.sidebar-footer{padding:14px 20px;border-top:1px solid rgba(255,255,255,.1);font-size:11px;opacity:.6}
.main{flex:1;overflow-y:auto;padding:24px}
.page-title{font-size:20px;font-weight:700;color:#1a3a5c;margin-bottom:20px}
.section{background:#fff;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:20px;overflow:hidden}
.section-header{padding:12px 18px;background:#f8f9fa;border-bottom:1px solid #e9ecef;font-weight:600;font-size:13px;color:#495057}
.section-body{padding:16px 18px}
.info-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}
.info-item{font-size:12px;color:#666}
.info-item strong{color:#333;display:block;margin-bottom:2px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{background:#e9ecef;padding:8px 10px;text-align:left;font-weight:600;color:#495057;border-bottom:2px solid #dee2e6}
td{padding:7px 10px;border-bottom:1px solid #f0f2f5;color:#333}
tr:hover td{background:#f8f9fa}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.badge-active{background:#d4edda;color:#155724}
.badge-inactive{background:#f8d7da;color:#721c24}
.action-row{display:flex;gap:10px;flex-wrap:wrap}
.btn{padding:8px 16px;border:none;border-radius:4px;font-size:13px;cursor:pointer;font-weight:500;text-decoration:none}
.btn-primary{background:#1a5f9e;color:#fff}
.btn-secondary{background:#6c757d;color:#fff}
.btn-danger{background:#dc3545;color:#fff}
</style>
</head>
<body>
<aside class="sidebar">
  <div class="sidebar-header">
    <h2>光華校務系統</h2>
    <p>台北市立光華高中</p>
  </div>
  <nav class="sidebar-nav">
    <a href="/portal" class="active">&#127968; 校務總覽</a>
    <a href="/portal/students">&#128100; 學生資料</a>
    <a href="/portal/grades">&#128220; 成績管理</a>
    <a href="/portal/attendance">&#128197; 請假紀錄</a>
    <a href="/portal/announce">&#128226; 教務公告</a>
    <a href="/admin/settings">&#9881;&#65039; 系統設定</a>
  </nav>
  <div class="sidebar-footer">
    陳志明（教務處）T00312<br>
    <a href="/logout" style="color:rgba(255,255,255,.5);font-size:11px">登出</a>
  </div>
</aside>
<main class="main">
  <div class="page-title">校務總覽</div>

  <div class="section">
    <div class="section-header">系統資訊</div>
    <div class="section-body">
      <div class="info-grid">
        <div class="info-item"><strong>伺服器</strong>edu-web-01.guanghua.edu.tw</div>
        <div class="info-item"><strong>作業系統</strong>Ubuntu 20.04.6 LTS</div>
        <div class="info-item"><strong>PHP / MySQL</strong>7.4.3 / 8.0.35</div>
        <div class="info-item"><strong>上次備份</strong>2024-03-14 02:00:01</div>
        <div class="info-item"><strong>目前使用者</strong>陳志明（教務處行政組）</div>
        <div class="info-item"><strong>上次登入</strong>2024-03-14 09:22:11 from 192.168.100.42</div>
      </div>
    </div>
  </div>

  <div class="section">
    <div class="section-header">學生 / 教職員帳號（最近更新）</div>
    <div class="section-body">
      <table>
        <thead>
          <tr><th>學號/工號</th><th>姓名</th><th>班級</th><th>Email</th><th>狀態</th></tr>
        </thead>
        <tbody>
          <tr><td>S110001</td><td>王大明</td><td>高一甲</td><td>s110001@guanghua.edu.tw</td><td><span class="badge badge-active">啟用</span></td></tr>
          <tr><td>S110002</td><td>李小華</td><td>高一甲</td><td>s110002@guanghua.edu.tw</td><td><span class="badge badge-active">啟用</span></td></tr>
          <tr><td>S110042</td><td>張雅婷</td><td>高一乙</td><td>s110042@guanghua.edu.tw</td><td><span class="badge badge-active">啟用</span></td></tr>
          <tr><td>T00312</td><td>陳志明</td><td>—</td><td>t00312@guanghua.edu.tw</td><td><span class="badge badge-active">啟用（教職員）</span></td></tr>
          <tr><td>T00156</td><td>林美玲</td><td>—</td><td>t00156@guanghua.edu.tw</td><td><span class="badge badge-active">啟用（教職員）</span></td></tr>
          <tr><td>S109311</td><td>吳建廷</td><td>高三丙</td><td>s109311@guanghua.edu.tw</td><td><span class="badge badge-inactive">停用</span></td></tr>
        </tbody>
      </table>
      <!-- pw_hash admin: $2y$10$KIXhfuJMLnzX9PLtS2vIJuGAh5wMPPkRQGWX/FtklSd1cjRnBaRnW -->
    </div>
  </div>

  <div class="section">
    <div class="section-header">最近成績異動紀錄</div>
    <div class="section-body">
      <table>
        <thead>
          <tr><th>學號</th><th>科目</th><th>原分數</th><th>新分數</th><th>異動人員</th><th>時間</th></tr>
        </thead>
        <tbody>
          <tr><td>S110001</td><td>數學</td><td>72</td><td>75</td><td>陳志明</td><td>2024-03-13 14:22</td></tr>
          <tr><td>S110042</td><td>英文</td><td>88</td><td>90</td><td>林美玲</td><td>2024-03-12 10:05</td></tr>
          <tr><td>S110002</td><td>物理</td><td>65</td><td>68</td><td>陳志明</td><td>2024-03-10 16:30</td></tr>
          <tr><td>S109311</td><td>化學</td><td>55</td><td>58</td><td>林美玲</td><td>2024-03-08 09:15</td></tr>
          <tr><td>S110001</td><td>國文</td><td>80</td><td>82</td><td>陳志明</td><td>2024-03-05 11:50</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="section">
    <div class="section-header">快速功能</div>
    <div class="section-body">
      <div class="action-row">
        <a href="/admin/export.php" class="btn btn-primary">匯出學生名冊</a>
        <a href="/admin/db-backup.php" class="btn btn-secondary">備份資料庫</a>
        <a href="/admin/announce.php" class="btn btn-secondary">發送公告</a>
        <a href="/admin/reset-passwords.php" class="btn btn-danger">重設帳號密碼</a>
      </div>
    </div>
  </div>
</main>
</body>
</html>`;
}

function pageWpLogin(host, errorMsg = '') {
  const token = randomBytes(16).toString('hex');
  const errorHtml = errorMsg
    ? `<div id="login_error"><strong>ERROR</strong>: ${errorMsg}</div>`
    : '';
  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Log In &lsaquo; 台北市立光華高中官網 &#8212; WordPress</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen-Sans,Ubuntu,Cantarell,"Helvetica Neue",sans-serif;background:#f0f0f1;color:#3c434a;font-size:13px}
#login{width:320px;margin:80px auto}
#login h1 a{display:block;width:84px;height:84px;background:#fff;border-radius:50%;margin:0 auto 20px;text-align:center;line-height:84px;font-size:40px;text-decoration:none;color:#1d2327}
#loginform{margin-top:20px;padding:26px 24px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.13);border-radius:4px}
#login_error{background:#fff;border-left:4px solid #d63638;margin-bottom:16px;padding:12px;font-size:13px;color:#d63638}
.input{width:100%;padding:8px;font-size:14px;border:1px solid #8c8f94;border-radius:4px;box-sizing:border-box;margin-top:4px}
.input:focus{border-color:#2271b1;outline:2px solid #2271b1;outline-offset:-1px}
p label{display:block;font-weight:600;margin:12px 0 0;color:#3c434a}
#wp-submit{background:#2271b1;border:none;color:#fff;cursor:pointer;font-size:13px;line-height:2;padding:2px 12px;border-radius:3px;width:100%;margin-top:20px}
#wp-submit:hover{background:#135e96}
#nav{margin:16px 0;font-size:13px;text-align:left}
#nav a{color:#2271b1;text-decoration:none}
#backtoblog{margin-top:8px;font-size:13px}
#backtoblog a{color:#50575e;text-decoration:none}
</style>
</head>
<body class="login login-action-login">
<div id="login">
<h1><a href="/" title="台北市立光華高中官網" tabindex="-1">W</a></h1>
${errorHtml}
<form name="loginform" id="loginform" action="/wp-login.php" method="post">
  <p>
    <label for="user_login">使用者名稱或電子郵件地址</label>
    <input type="text" name="log" id="user_login" class="input" value="" size="20" autocapitalize="off" autocomplete="username" required>
  </p>
  <p>
    <label for="user_pass">密碼</label>
    <input type="password" name="pwd" id="user_pass" class="input" value="" size="20" autocomplete="current-password" required>
  </p>
  <p class="forgetmenot">
    <input name="rememberme" type="checkbox" id="rememberme" value="forever">
    <label for="rememberme">記住我</label>
  </p>
  <input type="hidden" name="redirect_to" value="/wp-admin/">
  <input type="hidden" name="testcookie" value="1">
  <input type="hidden" name="_wpnonce" value="${token}">
  <p class="submit">
    <input type="submit" name="wp-submit" id="wp-submit" class="button button-primary button-large" value="登入">
  </p>
</form>
<p id="nav"><a href="/wp-login.php?action=lostpassword">忘記密碼？</a></p>
<p id="backtoblog"><a href="/">&larr; 返回 台北市立光華高中官網</a></p>
</div>
<!-- wp-login 6.4.3 - guanghua.edu.tw -->
</body>
</html>`;
}

function pagePhpMyAdmin() {
  const token = randomBytes(16).toString('hex');
  return `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>phpMyAdmin</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;font-size:13px;background:#f5f5f5;margin:0;padding:0}
#pma_navigation{background:#2a2a2a;color:#fff;padding:8px 16px;display:flex;align-items:center;gap:12px}
#pma_navigation strong{font-size:16px;color:#f79320}
#pma_navigation span{font-size:11px;color:#aaa}
#main_pane_left{max-width:420px;margin:60px auto;background:#fff;border:1px solid #ddd;border-radius:4px;overflow:hidden}
.pma-header{background:#2a2a2a;color:#fff;padding:14px 20px;font-weight:bold;font-size:14px}
.pma-body{padding:24px}
label{display:block;font-size:12px;color:#555;margin-bottom:4px;font-weight:bold}
input[type=text],input[type=password]{width:100%;padding:7px 10px;border:1px solid #ccc;border-radius:3px;font-size:13px;box-sizing:border-box;margin-bottom:14px}
input[type=text]:focus,input[type=password]:focus{border-color:#4a90d9;outline:none}
.server-row{font-size:12px;color:#666;margin-bottom:16px}
select{padding:4px 8px;border:1px solid #ccc;border-radius:3px;font-size:12px}
.go-btn{background:#4a90d9;color:#fff;border:none;padding:7px 20px;border-radius:3px;font-size:13px;cursor:pointer}
.go-btn:hover{background:#357abd}
.pma-footer{padding:10px 20px;background:#f9f9f9;border-top:1px solid #eee;font-size:11px;color:#999;text-align:right}
</style>
</head>
<body>
<div id="pma_navigation">
  <strong>phpMyAdmin</strong>
  <span>edu-db-01.guanghua.edu.tw</span>
</div>
<div id="main_pane_left">
  <div class="pma-header">登入</div>
  <div class="pma-body">
    <div class="server-row">
      伺服器：<strong>edu-db-01.guanghua.edu.tw</strong>
      &nbsp;|&nbsp;語言：<select><option>中文 - Chinese traditional</option><option>English</option></select>
    </div>
    <form method="POST" action="/phpmyadmin/index.php">
      <label for="input_username">使用者名稱：</label>
      <input type="text" id="input_username" name="pma_username" autocomplete="username" required>
      <label for="input_password">密碼：</label>
      <input type="password" id="input_password" name="pma_password" autocomplete="current-password" required>
      <input type="hidden" name="server" value="1">
      <input type="hidden" name="token" value="${token}">
      <button type="submit" class="go-btn">執行</button>
    </form>
  </div>
  <div class="pma-footer">phpMyAdmin 5.2.1</div>
</div>
</body>
</html>`;
}

function page403(host) {
  return `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>403 Forbidden</title></head>
<body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at ${host || 'localhost'} Port 80</address>
</body></html>`;
}

function page404(host) {
  return `<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head>
<body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.41 (Ubuntu) Server at ${host || 'localhost'} Port 80</address>
</body></html>`;
}

// ── Middleware ────────────────────────────────────────────────────────────────

// 記錄所有請求
app.use(async (req, res, next) => {
  const ip = getClientIp(req);
  const path = req.path || req.url?.split('?')[0] || '';
  const query = req.url?.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
  const ua = req.get('user-agent') || '';
  const bodyPreview = (req.body && Buffer.isBuffer(req.body)) ? req.body.slice(0, 512).toString('utf8').replace(/\0/g, '') : '';
  try { db.logDeceptionHit(req.method, path, query, ip, ua, bodyPreview); } catch (_) {}
  if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
  next();
});

// 路徑遍歷 & JNDI 攔截（在 Express 路徑正規化之前的 raw URL 偵測）
app.use((req, res, next) => {
  const raw = (req.url || '') + (req.body && Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '');
  if (/\/etc\/passwd|etc%2fpasswd|\.\.%2f|\.\.\//i.test(raw)) {
    applyFakeHeaders(res);
    return res.status(200).type('text/plain').send(fakePasswd());
  }
  if (/\$\{jndi:|%24%7bjndi|jndi%3a|ldap%3a/i.test(raw)) {
    applyFakeHeaders(res);
    return res.status(200).type('text/plain').send(fakeJndi());
  }
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────

app.get('/robots.txt', (req, res) => {
  applyFakeHeaders(res, { cache: true });
  res.status(200).type('text/plain').send(
    `User-agent: *\nDisallow: /admin/\nDisallow: /portal/\nDisallow: /student-data/\nDisallow: /backup/\nDisallow: /.env\nDisallow: /db/\nDisallow: /phpmyadmin/\nDisallow: /teacher/grade-export/\n# 光華校務系統\nSitemap: /sitemap.xml\n`
  );
});

app.get('/favicon.ico', (req, res) => {
  applyFakeHeaders(res, { cache: true });
  // 最小有效 ICO 檔案（16x16，1 color）
  const ico = Buffer.from(
    '000001000100101000000100200068040000160000002800000010000000200000000100200000000000000400000000000000000000000000000000000000' +
    '1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff1a5f9eff',
    'hex'
  );
  res.status(200).type('image/x-icon').send(ico);
});

app.get('/sitemap.xml', (req, res) => {
  applyFakeHeaders(res, { cache: true });
  const host = req.headers.host || 'guanghua.edu.tw';
  res.status(200).type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n<url><loc>http://${host}/</loc></url>\n<url><loc>http://${host}/login</loc></url>\n<url><loc>http://${host}/portal</loc></url>\n<url><loc>http://${host}/admin</loc></url>\n</urlset>`
  );
});

app.all('/.env', (req, res) => {
  applyFakeHeaders(res);
  res.status(403).type('text/html').send(page403(req.headers.host));
});

app.all('/.git*', (req, res) => {
  applyFakeHeaders(res);
  res.status(403).type('text/html').send(page403(req.headers.host));
});

// phpMyAdmin
app.all('/phpmyadmin*', (req, res) => {
  applyFakeHeaders(res);
  if (req.method === 'POST') {
    const fields = parseFormBody(req.body);
    const ip = getClientIp(req);
    try { db.logCredential(ip, req.get('user-agent') || '', fields.pma_username || '', fields.pma_password || '', req.path, 1); } catch (_) {}
  }
  res.status(200).type('text/html').send(pagePhpMyAdmin());
});

app.all('/pma*', (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pagePhpMyAdmin());
});

app.all('/phpMyAdmin*', (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pagePhpMyAdmin());
});

// WordPress
app.post('/wp-login.php', (req, res) => {
  const fields = parseFormBody(req.body);
  const ip = getClientIp(req);
  try { db.logCredential(ip, req.get('user-agent') || '', fields.log || '', fields.pwd || '', '/wp-login.php', 1); } catch (_) {}
  applyFakeHeaders(res);
  res.setHeader('Set-Cookie', [
    `PHPSESSID=${randomBytes(16).toString('hex')}; path=/; HttpOnly`,
    `wordpress_test_cookie=WP+Cookie+check; path=/wp-login.php`,
  ]);
  res.status(200).type('text/html').send(
    pageWpLogin(req.headers.host, `The password you entered for the username <strong>${(fields.log || '').replace(/[<>]/g, '')||'unknown'}</strong> is incorrect.`)
  );
});

app.all('/wp-login.php', (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pageWpLogin(req.headers.host));
});

app.all('/wp-admin*', (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pageWpLogin(req.headers.host));
});

app.all('/wordpress*', (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pageWpLogin(req.headers.host));
});

// 假後台：需要 cookie 才能進入
app.get(['/dashboard', '/portal', '/portal/*'], (req, res) => {
  const ip = getClientIp(req);
  const sessCookie = parseCookie(req.headers.cookie, '_sess');
  const count = readSession(sessCookie, ip);
  if (count < FAIL_BEFORE_SUCCESS) {
    applyFakeHeaders(res);
    return res.redirect(302, '/login');
  }
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pagePortal());
});

// 登出
app.all('/logout', (req, res) => {
  applyFakeHeaders(res);
  res.setHeader('Set-Cookie', '_sess=; Max-Age=0; path=/; HttpOnly');
  res.redirect(302, '/login');
});

// 主登入頁
app.get(['/login', '/signin', '/'], (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pageLogin());
});

// POST 登入：記錄帳密，前 N 次失敗，之後重導後台
app.post(['/login', '/signin'], (req, res) => {
  const ip = getClientIp(req);
  const ua = req.get('user-agent') || '';
  const fields = parseFormBody(req.body);
  const username = fields.username || '';
  const password = fields.password || '';
  const sessCookie = parseCookie(req.headers.cookie, '_sess');
  const count = readSession(sessCookie, ip);
  const attemptNum = count + 1;

  try { db.logCredential(ip, ua, username, password, req.path, attemptNum); } catch (_) {}

  applyFakeHeaders(res);

  if (count < FAIL_BEFORE_SUCCESS) {
    res.setHeader('Set-Cookie', `_sess=${signSession(attemptNum, ip)}; path=/; HttpOnly`);
    return res.status(200).type('text/html').send(
      pageLogin('帳號或密碼錯誤，請重新輸入。如連續輸入錯誤 5 次，帳號將被鎖定 30 分鐘。')
    );
  }

  res.setHeader('Set-Cookie', `_sess=${signSession(99, ip)}; path=/; HttpOnly`);
  res.redirect(302, '/portal');
});

// Admin 入口
app.all(['/admin', '/administrator', '/manage', '/admin/*', '/administrator/*'], (req, res) => {
  const ip = getClientIp(req);
  const sessCookie = parseCookie(req.headers.cookie, '_sess');
  const count = readSession(sessCookie, ip);
  if (count >= FAIL_BEFORE_SUCCESS) {
    applyFakeHeaders(res);
    return res.status(404).type('text/html').send(page404(req.headers.host));
  }
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(pageLogin());
});

// phpinfo
app.all(['/phpinfo', '/phpinfo.php', '/info.php', '/phpinfo*'], (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/html').send(fakePhpInfo());
});

// /etc/passwd 直接路徑
app.all('/etc/passwd', (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/plain').send(fakePasswd());
});

// Shell injection paths
app.all(['/shell', '/cmd', '/exec', '/shell.php', '/cmd.php'], (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('text/plain').send(fakeShell(req));
});

// Fake API
app.all(['/api/*', '/v1/*', '/v2/*'], (req, res) => {
  applyFakeHeaders(res);
  res.status(200).type('application/json').send(fakeApi(req));
});

// SQL/shell pattern 偵測（攻擊 payload 藏在 query string 或 body）
app.all('*', (req, res, next) => {
  const raw = ((req.url || '') + (req.body && Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '')).toLowerCase();

  if (/whoami|ifconfig|ipconfig|cmd\.exe|powershell|bin%2fsh|bin%2fbash|%2fbin%2fsh/.test(raw)) {
    applyFakeHeaders(res);
    return res.status(200).type('text/plain').send(fakeShell(req));
  }
  if (/phpinfo|eval\s*\(|system\s*\(|exec\s*\(|passthru|shell_exec|popen|proc_open/.test(raw)) {
    applyFakeHeaders(res);
    return res.status(200).type('text/html').send(fakePhpInfo());
  }
  if (/union.*select|base64_decode|0x[0-9a-f]+|select\s+.*from|insert\s+into/.test(raw)) {
    applyFakeHeaders(res);
    return res.status(200).type('application/json').send(fakeSql());
  }

  next();
});

// 404 catch-all
app.all('*', (req, res) => {
  applyFakeHeaders(res);
  res.status(404).type('text/html').send(page404(req.headers.host));
});

export { app as deceptionApp };

const __filename = fileURLToPath(import.meta.url);
const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(__filename);
if (isMain) {
  const { port, bindHost } = config.deception;
  app.listen(port, bindHost, () => {
    console.log(`[誘騙服務] 假系統監聽 http://${bindHost}:${port}（供 Nginx proxy 導向）`);
  });
}
