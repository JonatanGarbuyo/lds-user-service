import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./site/', import.meta.url));
const port = Number(process.env.SITE_PORT ?? 4173);
const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8'
};

createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://app.localhost').pathname;
  const name = pathname === '/' ? 'index.html' : pathname.slice(1);
  const path = normalize(join(root, name));
  if (!path.startsWith(root)) {
    response.writeHead(404).end();
    return;
  }
  try {
    const body = await readFile(path);
    response.writeHead(200, {
      'Content-Type': contentTypes[extname(path)] ?? 'application/octet-stream',
      'Cache-Control': name === 'editorial.html' ? 'public, max-age=60' : 'no-store'
    });
    response.end(body);
  } catch {
    response.writeHead(404).end();
  }
}).listen(port, '127.0.0.1');
