import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { localCommitsOnUpstream, sync } from '../src/client/ops.js';
import { Workspace } from '../src/client/workspace.js';

const env = { ...process.env, GIT_AUTHOR_NAME: 'a', GIT_AUTHOR_EMAIL: 'a', GIT_COMMITTER_NAME: 'a', GIT_COMMITTER_EMAIL: 'a' };
const git = (dir, ...args) => execFileSync('git', args, { cwd: dir, env, encoding: 'utf8' }).trim();
const commit = (dir, file, text, msg = file) => {
  fs.writeFileSync(path.join(dir, file), text);
  git(dir, 'add', file);
  git(dir, 'commit', '-qm', msg);
  return git(dir, 'rev-parse', 'HEAD');
};

// A server repo and a contributor clone of it; the clone's history is main as it was.
function setup(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'td-sync-rewrite-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const server = path.join(root, 'server');
  fs.mkdirSync(server);
  git(server, 'init', '-q', '-b', 'main');
  commit(server, 'a.cpp', 'a\n');
  commit(server, 'b.cpp', 'b\n');
  commit(server, 'c.cpp', 'c\n');
  const clone = path.join(root, 'clone');
  git(root, 'clone', '-q', server, clone);
  const ws = { git: (...args) => git(clone, ...args) };
  // The server rewrites every commit after the first (new authors, same changes).
  const rewrite = () => {
    git(server, 'checkout', '-q', '--detach', 'HEAD~2');
    for (const [f, text] of [['b.cpp', 'b\n'], ['c.cpp', 'c\n']]) {
      fs.writeFileSync(path.join(server, f), text);
      git(server, 'add', f);
      execFileSync('git', ['commit', '-qm', f], { cwd: server, env: { ...env, GIT_AUTHOR_NAME: 'renamed' } });
    }
    git(server, 'branch', '-f', 'main', 'HEAD');
    git(server, 'checkout', '-q', 'main');
    git(clone, 'fetch', '-q', 'origin');
  };
  return { server, clone, ws, rewrite };
}

test('a clone whose commits main has under new IDs may follow the rewrite', (t) => {
  const { ws, rewrite } = setup(t);
  rewrite();
  assert.throws(() => ws.git('merge', '--ff-only', '@{u}'), 'a fast-forward is impossible after the rewrite');
  assert.equal(localCommitsOnUpstream(ws), true, 'every commit of the clone is on main by content');
});

test('a clone with a commit main does not have stays where it is', (t) => {
  const { clone, ws, rewrite } = setup(t);
  commit(clone, 'mine.cpp', 'unpublished work\n');
  rewrite();
  assert.equal(localCommitsOnUpstream(ws), false, 'its own work would be lost');
});

test('an up-to-date clone or one only behind main is simply not ahead', (t) => {
  const { server, ws } = setup(t);
  assert.equal(localCommitsOnUpstream(ws), true);
  commit(server, 'd.cpp', 'd\n');
  ws.git('fetch', '-q', 'origin');
  assert.equal(localCommitsOnUpstream(ws), true, 'behind is the ordinary fast-forward case');
});

test('sync verifies target bytes even for the same version in a dirty workspace', async (t) => {
  const { clone } = setup(t);
  const ws = new Workspace(clone);
  const old = Buffer.from('old target');
  const current = Buffer.from('new target');
  const sha256 = createHash('sha256').update(current).digest('hex');
  let downloads = 0;
  let payload = current;
  const version = { id: 'clean', sha256, size: current.length };
  const server = http.createServer((req, res) => {
    if (req.url === '/api/info') return res.end(JSON.stringify({ version }));
    if (req.url === '/api/symbols?version=clean') return res.end(JSON.stringify({ version: 'clean', symbols: [] }));
    if (req.url === '/target' && req.headers.authorization === 'Bearer contributor') {
      downloads++;
      return res.end(payload);
    }
    res.writeHead(404).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  ws.config = { server: `http://127.0.0.1:${server.address().port}`, token: 'contributor' };
  version.download = `${ws.config.server}/target`;
  ws.save();
  fs.writeFileSync(ws.targetFile, old);
  fs.writeFileSync(ws.symbolsFile, JSON.stringify({ version: 'clean', symbols: [] }));
  fs.writeFileSync(path.join(clone, 'a.cpp'), 'unfinished');

  const result = await sync(ws);
  assert.equal(result.fastForwarded, false);
  assert.equal(fs.readFileSync(path.join(clone, 'a.cpp'), 'utf8'), 'unfinished');
  assert.deepEqual(result.target, { version: 'clean', sha256, updated: true });
  assert.deepEqual(fs.readFileSync(ws.targetFile), current);
  assert.equal((await sync(ws)).target.updated, false);
  assert.equal(downloads, 1, 'a verified target is not downloaded again');

  fs.unlinkSync(ws.targetFile);
  await sync(ws);
  assert.deepEqual(fs.readFileSync(ws.targetFile), current);
  fs.writeFileSync(ws.targetFile, old);
  payload = Buffer.from('corrupt download');
  await assert.rejects(sync(ws), /hash mismatch/);
  assert.deepEqual(fs.readFileSync(ws.targetFile), old);
  version.download = null;
  await assert.rejects(sync(ws), new RegExp(sha256));
  assert.deepEqual(fs.readFileSync(ws.targetFile), old);
});
