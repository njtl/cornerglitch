const http = require('http');
const { URL } = require('url');

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (req.method === 'GET' && url.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body><h1>Express Target</h1><p>Default config, no hardening.</p></body></html>');
  } else if (req.method === 'GET' && url.pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok');
  } else if (req.method === 'POST' && url.pathname === '/login') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<html><body><h1>Login received</h1><pre>${body}</pre></body></html>`);
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
  }
});

server.listen(3000, '0.0.0.0', () => {
  console.log('Express target listening on :3000');
});
