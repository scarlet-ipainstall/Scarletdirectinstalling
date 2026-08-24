import express from 'express';
import multer from 'multer';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } from '@aws-sdk/client-s3';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const exec = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 10000;
const RETENTION_DAYS = 14;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;
const ROOT = '/tmp/scarlet';
const upload = multer({ dest: ROOT, limits: { fileSize: 1024 * 1024 * 1024, files: 3 } });
const builds = new Map();

app.set('trust proxy', 1);
app.use(express.json());

const r2Enabled = Boolean(process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY && process.env.R2_BUCKET_NAME && process.env.R2_PUBLIC_BASE_URL);
const r2 = r2Enabled ? new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY }
}) : null;

await fs.mkdir(ROOT, { recursive: true });
app.use(express.static('public'));

function safeName(name) { return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_'); }
function publicBase(req) {
  const configured = process.env.PUBLIC_BASE_URL?.trim();
  if (configured) return configured.replace(/\/$/, '').replace(/^http:\/\//i, 'https://');
  return `https://${req.get('host')}`;
}
function assertHttpsUrl(value, name) { if (!/^https:\/\//i.test(value)) throw new Error(`${name} must use HTTPS`); }

async function put(key, data, contentType) {
  await r2.send(new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key, Body: data, ContentType: contentType, CacheControl: 'no-cache, no-store, must-revalidate' }));
}

async function getBundleIdFromIpa(ipaPath) {
  const script = `import plistlib, sys, zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z:\n    names=[n for n in z.namelist() if n.startswith('Payload/') and n.endswith('.app/Info.plist')]\n    if not names: raise SystemExit('Payload/*.app/Info.plist not found')\n    with z.open(names[0]) as f:\n        p=plistlib.load(f)\n    bid=p.get('CFBundleIdentifier')\n    if not isinstance(bid,str) or not bid: raise SystemExit('CFBundleIdentifier not found')\n    print(bid)`;
  const { stdout } = await exec('python3', ['-c', script, ipaPath], { timeout: 30 * 1000, maxBuffer: 256 * 1024 });
  const bundleId = stdout.trim();
  if (!/^[A-Za-z0-9.-]+$/.test(bundleId)) throw new Error('Invalid Bundle ID in IPA.');
  return bundleId;
}

async function listR2BuildObjects(id) {
  if (!r2Enabled) return [];
  const listed = await r2.send(new ListObjectsV2Command({ Bucket: process.env.R2_BUCKET_NAME, Prefix: `builds/${id}/` }));
  return (listed.Contents || []).filter(x => x.Key);
}

async function deleteBuildObjects(id, knownKey = null) {
  if (!r2Enabled) return;
  const keys = [`builds/${id}/manifest.plist`];
  if (knownKey) keys.push(knownKey);
  try {
    const objects = await listR2BuildObjects(id);
    for (const obj of objects) if (obj.Key && !keys.includes(obj.Key)) keys.push(obj.Key);
  } catch (e) { console.error('R2 list failed during deletion:', e.message); }
  await Promise.all(keys.map(async key => {
    try { await r2.send(new DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key })); }
    catch (e) { console.error(`R2 delete failed for ${key}:`, e.message); }
  }));
}

async function cleanupExpiredBuilds() {
  const cutoff = Date.now() - RETENTION_MS;
  for (const [id, b] of builds.entries()) {
    if (b.createdAt <= cutoff) {
      await fs.rm(b.file, { force: true }).catch(() => {});
      await fs.rm(path.join(ROOT, `${id}.ipa`), { force: true }).catch(() => {});
      if (r2Enabled) await deleteBuildObjects(id, b.key);
      builds.delete(id);
      console.log(`Expired build removed: ${id}`);
    }
  }
  if (!r2Enabled) return;
  try {
    let token;
    do {
      const listed = await r2.send(new ListObjectsV2Command({ Bucket: process.env.R2_BUCKET_NAME, Prefix: 'builds/', ContinuationToken: token }));
      const expiredIds = new Set();
      for (const obj of listed.Contents || []) {
        if (!obj.Key || !obj.LastModified || obj.LastModified.getTime() > cutoff) continue;
        const parts = obj.Key.split('/');
        if (parts.length >= 2 && /^[a-f0-9]{16}$/.test(parts[1])) expiredIds.add(parts[1]);
      }
      for (const id of expiredIds) {
        await deleteBuildObjects(id, builds.get(id)?.key || null);
        builds.delete(id);
        console.log(`Expired R2 build removed: ${id}`);
      }
      token = listed.IsTruncated ? listed.NextContinuationToken : undefined;
    } while (token);
  } catch (e) { console.error('R2 cleanup failed:', e.message); }
}

// Automatic retention cleanup: signed files and manifests are removed after 14 days.
setInterval(() => cleanupExpiredBuilds().catch(e => console.error('Cleanup error:', e)), 6 * 60 * 60 * 1000);
setTimeout(() => cleanupExpiredBuilds().catch(e => console.error('Initial cleanup error:', e)), 10_000);

app.post('/api/sign', upload.fields([
  { name: 'ipa', maxCount: 1 },
  { name: 'p12', maxCount: 1 },
  { name: 'mobileprovision', maxCount: 1 }
]), async (req, res) => {
  const files = req.files || {};
  const ipa = files.ipa?.[0];
  const p12 = files.p12?.[0];
  const prov = files.mobileprovision?.[0];
  const password = String(req.body.password || '');
  const version = String(req.body.version || '1.0').replace(/[^A-Za-z0-9._-]/g, '');
  if (!ipa || !p12 || !prov) return res.status(400).json({ error: 'Upload an IPA, .p12 certificate, and .mobileprovision profile.' });
  if (!password) return res.status(400).json({ error: 'A .p12 password is required.' });

  const id = crypto.randomBytes(8).toString('hex');
  const out = path.join(ROOT, `${id}-signed.ipa`);
  const appName = safeName(ipa.originalname).replace(/\.ipa$/i, '') || 'Signed App';
  const filename = `${appName}-signed.ipa`;
  const createdAt = Date.now();
  const expiresAt = createdAt + RETENTION_MS;

  try {
    const bundleId = await getBundleIdFromIpa(ipa.path);
    try {
      await exec('zsign', ['-f', '-k', p12.path, '-p', password, '-m', prov.path, '-r', version, '-o', out, ipa.path], { timeout: 10 * 60 * 1000, maxBuffer: 2 * 1024 * 1024 });
    } catch (signError) {
      const detail = String(signError.stderr || signError.stdout || signError.message).slice(0, 2000);
      return res.status(400).json({ error: `Signing failed for Bundle ID ${bundleId}. The uploaded .p12 and provisioning profile must authorize this app and belong to the same Apple signing setup.`, bundleId, detail });
    }

    const ipaData = await fs.readFile(out);
    const key = `builds/${id}/${filename}`;
    const base = publicBase(req);
    assertHttpsUrl(base, 'Public base URL');
    let download;
    if (r2Enabled) {
      await put(key, ipaData, 'application/octet-stream');
      // Keep the IPA behind the server so the 14-day expiration also applies to downloads.
      download = `${base}/download/${id}`;
    } else {
      await fs.copyFile(out, path.join(ROOT, `${id}.ipa`));
      download = `${base}/download/${id}`;
    }
    assertHttpsUrl(download, 'IPA download URL');

    const manifest = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${download}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${bundleId}</string><key>bundle-version</key><string>${version}</string><key>kind</key><string>software</string><key>title</key><string>${appName}</string></dict></dict></array></dict></plist>`;
    const manifestKey = `builds/${id}/manifest.plist`;
    if (r2Enabled) await put(manifestKey, Buffer.from(manifest), 'application/xml');
    builds.set(id, { file: path.join(ROOT, `${id}.ipa`), name: filename, manifest, key, persistent: r2Enabled, createdAt });

    const manifestUrl = `${base}/manifest/${id}.plist`;
    assertHttpsUrl(manifestUrl, 'Manifest URL');
    res.json({ id, bundleId, download, manifest: manifestUrl, install: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`, persistent: r2Enabled, retentionDays: RETENTION_DAYS, createdAt: new Date(createdAt).toISOString(), expiresAt: new Date(expiresAt).toISOString() });
  } catch (e) {
    res.status(500).json({ error: 'Signing failed. Check that the certificate, password, provisioning profile, and app authorization are valid.', detail: String(e.stderr || e.message).slice(0, 1500) });
  } finally {
    for (const f of [ipa, p12, prov]) if (f?.path) await fs.rm(f.path, { force: true }).catch(() => {});
    await fs.rm(out, { force: true }).catch(() => {});
  }
});

app.delete('/api/build/:id', async (req, res) => {
  const id = String(req.params.id || '');
  if (!/^[a-f0-9]{16}$/.test(id)) return res.status(400).json({ error: 'Invalid build ID.' });
  try {
    const b = builds.get(id);
    if (r2Enabled) await deleteBuildObjects(id, b?.key || null);
    if (b?.file) await fs.rm(b.file, { force: true }).catch(() => {});
    await fs.rm(path.join(ROOT, `${id}.ipa`), { force: true }).catch(() => {});
    builds.delete(id);
    res.json({ ok: true, id });
  } catch (e) { res.status(500).json({ error: 'Could not delete this build.', detail: String(e.message || e).slice(0, 500) }); }
});

app.get('/download/:id', async (req, res) => {
  const id = req.params.id;
  const b = builds.get(id);
  if (b && !b.persistent) {
    if (Date.now() >= b.createdAt + RETENTION_MS) return res.status(404).send('This build has expired.');
    return res.download(b.file, b.name);
  }
  if (!r2Enabled) return res.status(404).send('Build not found.');
  try {
    const objects = await listR2BuildObjects(id);
    const ipaObject = objects.find(x => x.Key.endsWith('.ipa'));
    if (!ipaObject || !ipaObject.LastModified || Date.now() - ipaObject.LastModified.getTime() >= RETENTION_MS) {
      await deleteBuildObjects(id, ipaObject?.Key || null);
      return res.status(404).send('This build has expired.');
    }
    const obj = await r2.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: ipaObject.Key }));
    res.set('Cache-Control', 'no-store');
    res.set('Content-Type', 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="${safeName(path.basename(ipaObject.Key))}"`);
    obj.Body.pipe(res);
  } catch (e) { res.status(404).send('Build not found or expired.'); }
});

app.get('/manifest/:id.plist', async (req, res) => {
  const id = req.params.id;
  if (!/^[a-f0-9]{16}$/.test(id)) return res.status(404).send('Manifest not found.');
  if (r2Enabled) {
    try {
      const obj = await r2.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: `builds/${id}/manifest.plist` }));
      if (!obj.LastModified || Date.now() - obj.LastModified.getTime() >= RETENTION_MS) {
        await deleteBuildObjects(id, null);
        return res.status(404).send('Manifest expired.');
      }
      res.set('Cache-Control', 'no-store');
      res.type('application/xml').send(Buffer.from(await obj.Body.transformToByteArray()));
      return;
    } catch {}
  }
  const b = builds.get(id);
  if (!b || Date.now() >= b.createdAt + RETENTION_MS) return res.status(404).send('Manifest expired.');
  res.set('Cache-Control', 'no-store');
  res.type('application/xml').send(b.manifest);
});

app.get('/health', (_req, res) => res.json({ ok: true, persistentStorage: r2Enabled, retentionDays: RETENTION_DAYS }));
app.listen(PORT, () => console.log(`Scarlet Direct Installing listening on ${PORT}; retention=${RETENTION_DAYS} days; R2=${r2Enabled}`));
