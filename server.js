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
const r2 = r2Enabled ? new S3Client({ region: 'auto', endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`, credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY } }) : null;

const KITSCERTS = {
  'hsbc-bank-plc': {
    label: 'HSBC Bank Plc',
    p12Path: process.env.KITSCERT_HSBC_P12_PATH || '/etc/secrets/hsbc.p12',
    provPath: process.env.KITSCERT_HSBC_PROV_PATH || '/etc/secrets/hsbc.mobileprovision',
    password: process.env.KITSCERT_HSBC_PASSWORD || '',
    p12Base64: process.env.KITSCERT_HSBC_P12_B64 || '',
    provBase64: process.env.KITSCERT_HSBC_PROV_B64 || ''
  }
};

await fs.mkdir(ROOT, { recursive: true });
app.use(express.static('public'));

function safeName(name) { return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_'); }
function publicBase(req) { const configured = process.env.PUBLIC_BASE_URL?.trim(); return (configured ? configured.replace(/\/$/, '') : `https://${req.get('host')}`).replace(/^http:\/\//i, 'https://'); }
function assertHttpsUrl(value, name) { if (!/^https:\/\//i.test(value)) throw new Error(`${name} must use HTTPS`); }
async function put(key, data, contentType) { await r2.send(new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key, Body: data, ContentType: contentType, CacheControl: 'no-cache, no-store, must-revalidate' })); }

async function materializeBase64Secret(preset) {
  // Render Secret Files are text-oriented. Base64 environment variables allow binary .p12/.mobileprovision files to be stored safely.
  if (preset.p12Base64) {
    await fs.writeFile(preset.p12Path, Buffer.from(preset.p12Base64.replace(/\s+/g, ''), 'base64'), { mode: 0o600 });
  }
  if (preset.provBase64) {
    await fs.writeFile(preset.provPath, Buffer.from(preset.provBase64.replace(/\s+/g, ''), 'base64'), { mode: 0o600 });
  }
}

async function getBundleIdFromIpa(ipaPath) {
  const script = `import plistlib,sys,zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z:\n names=[n for n in z.namelist() if n.startswith('Payload/') and n.endswith('.app/Info.plist')]\n if not names: raise SystemExit('Payload/*.app/Info.plist not found')\n with z.open(names[0]) as f: p=plistlib.load(f)\n bid=p.get('CFBundleIdentifier')\n if not isinstance(bid,str) or not bid: raise SystemExit('CFBundleIdentifier not found')\n print(bid)`;
  const { stdout } = await exec('python3', ['-c', script, ipaPath], { timeout: 30000, maxBuffer: 256 * 1024 });
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
  try { for (const obj of await listR2BuildObjects(id)) if (obj.Key && !keys.includes(obj.Key)) keys.push(obj.Key); } catch (e) { console.error('R2 list failed:', e.message); }
  await Promise.all(keys.map(async key => { try { await r2.send(new DeleteObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key })); } catch (e) { console.error(`R2 delete failed for ${key}:`, e.message); } }));
}
async function cleanupExpiredBuilds() {
  const cutoff = Date.now() - RETENTION_MS;
  for (const [id, b] of builds.entries()) if (b.createdAt <= cutoff) { await fs.rm(b.file, { force: true }).catch(() => {}); if (r2Enabled) await deleteBuildObjects(id, b.key); builds.delete(id); }
  if (!r2Enabled) return;
  try {
    const listed = await r2.send(new ListObjectsV2Command({ Bucket: process.env.R2_BUCKET_NAME, Prefix: 'builds/' }));
    const ids = new Set();
    for (const obj of listed.Contents || []) if (obj.Key && obj.LastModified && obj.LastModified.getTime() <= cutoff) { const p = obj.Key.split('/'); if (p[1] && /^[a-f0-9]{16}$/.test(p[1])) ids.add(p[1]); }
    for (const id of ids) { await deleteBuildObjects(id, builds.get(id)?.key || null); builds.delete(id); }
  } catch (e) { console.error('R2 cleanup failed:', e.message); }
}
setInterval(() => cleanupExpiredBuilds().catch(console.error), 6 * 60 * 60 * 1000);
setTimeout(() => cleanupExpiredBuilds().catch(console.error), 10000);

app.post('/api/sign', upload.fields([{ name: 'ipa', maxCount: 1 }, { name: 'p12', maxCount: 1 }, { name: 'mobileprovision', maxCount: 1 }]), async (req, res) => {
  const files = req.files || {};
  const ipa = files.ipa?.[0];
  const uploadedP12 = files.p12?.[0];
  const uploadedProv = files.mobileprovision?.[0];
  const presetId = String(req.body.certificatePreset || '').trim();
  const version = String(req.body.version || '1.0').replace(/[^A-Za-z0-9._-]/g, '');
  let p12Path = uploadedP12?.path;
  let provPath = uploadedProv?.path;
  let password = String(req.body.password || '');

  try {
    if (presetId) {
      const preset = KITSCERTS[presetId];
      if (!preset) return res.status(400).json({ error: 'Unknown KitsCerts certificate.' });
      await materializeBase64Secret(preset);
      if (!preset.password) return res.status(503).json({ error: `${preset.label} password is not configured on the server yet.` });
      p12Path = preset.p12Path;
      provPath = preset.provPath;
      password = preset.password;
      try { await fs.access(p12Path); await fs.access(provPath); } catch { return res.status(503).json({ error: `${preset.label} certificate files are not configured on the server yet. Add the actual binary files as base64 environment variables or valid server secret files.` }); }
    }
    if (!ipa || !p12Path || !provPath) return res.status(400).json({ error: 'Upload an IPA and provide a KitsCerts certificate or your own .p12/profile.' });
    if (!password) return res.status(400).json({ error: 'A .p12 password is required.' });

    const bundleId = await getBundleIdFromIpa(ipa.path);
    const id = crypto.randomBytes(8).toString('hex');
    const out = path.join(ROOT, `${id}-signed.ipa`);
    const appName = safeName(ipa.originalname).replace(/\.ipa$/i, '') || 'Signed App';
    const filename = `${appName}-signed.ipa`;
    const createdAt = Date.now();
    const expiresAt = createdAt + RETENTION_MS;

    try {
      await exec('zsign', ['-f', '-k', p12Path, '-p', password, '-m', provPath, '-r', version, '-o', out, ipa.path], { timeout: 10 * 60 * 1000, maxBuffer: 2 * 1024 * 1024 });
    } catch (signError) {
      const detail = String(signError.stderr || signError.stdout || signError.message).slice(0, 2500);
      return res.status(400).json({ error: `Signing failed for Bundle ID ${bundleId}. The certificate and provisioning profile must authorize this app; this check cannot be bypassed.`, bundleId, detail });
    }

    const ipaData = await fs.readFile(out);
    const key = `builds/${id}/${filename}`;
    const base = publicBase(req);
    assertHttpsUrl(base, 'Public base URL');
    let download;
    if (r2Enabled) { await put(key, ipaData, 'application/octet-stream'); download = `${base}/download/${id}`; }
    else { await fs.copyFile(out, path.join(ROOT, `${id}.ipa`)); download = `${base}/download/${id}`; }
    assertHttpsUrl(download, 'IPA download URL');
    const manifest = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${download}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${bundleId}</string><key>bundle-version</key><string>${version}</string><key>kind</key><string>software</string><key>title</key><string>${appName}</string></dict></dict></array></dict></plist>`;
    const manifestKey = `builds/${id}/manifest.plist`;
    if (r2Enabled) await put(manifestKey, Buffer.from(manifest), 'application/xml');
    builds.set(id, { file: path.join(ROOT, `${id}.ipa`), name: filename, manifest, key, persistent: r2Enabled, createdAt });
    const manifestUrl = `${base}/manifest/${id}.plist`;
    assertHttpsUrl(manifestUrl, 'Manifest URL');
    return res.json({ id, bundleId, certificatePreset: presetId || null, download, manifest: manifestUrl, install: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`, persistent: r2Enabled, retentionDays: RETENTION_DAYS, createdAt: new Date(createdAt).toISOString(), expiresAt: new Date(expiresAt).toISOString() });
  } catch (e) {
    return res.status(500).json({ error: 'Signing failed. Check the certificate, password, provisioning profile, and app authorization.', detail: String(e.stderr || e.message).slice(0, 1500) });
  } finally {
    for (const f of [ipa, uploadedP12, uploadedProv]) if (f?.path) await fs.rm(f.path, { force: true }).catch(() => {});
  }
});

app.delete('/api/build/:id', async (req, res) => {
  const id = String(req.params.id || '');
  if (!/^[a-f0-9]{16}$/.test(id)) return res.status(400).json({ error: 'Invalid build ID.' });
  try { const b = builds.get(id); if (r2Enabled) await deleteBuildObjects(id, b?.key || null); if (b?.file) await fs.rm(b.file, { force: true }).catch(() => {}); await fs.rm(path.join(ROOT, `${id}.ipa`), { force: true }).catch(() => {}); builds.delete(id); res.json({ ok: true, id }); }
  catch (e) { res.status(500).json({ error: 'Could not delete this build.', detail: String(e.message || e).slice(0, 500) }); }
});

app.get('/download/:id', async (req, res) => {
  const id = req.params.id, b = builds.get(id);
  if (b && !b.persistent) { if (Date.now() >= b.createdAt + RETENTION_MS) return res.status(404).send('This build has expired.'); return res.download(b.file, b.name); }
  if (!r2Enabled) return res.status(404).send('Build not found.');
  try { const objects = await listR2BuildObjects(id); const ipaObject = objects.find(x => x.Key.endsWith('.ipa')); if (!ipaObject || !ipaObject.LastModified || Date.now() - ipaObject.LastModified.getTime() >= RETENTION_MS) { await deleteBuildObjects(id, ipaObject?.Key || null); return res.status(404).send('This build has expired.'); } const obj = await r2.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: ipaObject.Key })); res.set('Cache-Control', 'no-store'); res.set('Content-Type', 'application/octet-stream'); res.set('Content-Disposition', `attachment; filename="${safeName(path.basename(ipaObject.Key))}"`); obj.Body.pipe(res); }
  catch { res.status(404).send('Build not found or expired.'); }
});

app.get('/manifest/:id.plist', async (req, res) => {
  const id = req.params.id; if (!/^[a-f0-9]{16}$/.test(id)) return res.status(404).send('Manifest not found.');
  if (r2Enabled) { try { const obj = await r2.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: `builds/${id}/manifest.plist` })); if (!obj.LastModified || Date.now() - obj.LastModified.getTime() >= RETENTION_MS) { await deleteBuildObjects(id, null); return res.status(404).send('Manifest expired.'); } res.set('Cache-Control', 'no-store'); res.type('application/xml').send(Buffer.from(await obj.Body.transformToByteArray())); return; } catch {} }
  const b = builds.get(id); if (!b || Date.now() >= b.createdAt + RETENTION_MS) return res.status(404).send('Manifest expired.'); res.set('Cache-Control', 'no-store'); res.type('application/xml').send(b.manifest);
});
app.get('/health', (_req, res) => res.json({ ok: true, persistentStorage: r2Enabled, retentionDays: RETENTION_DAYS, kitsCerts: Object.fromEntries(Object.entries(KITSCERTS).map(([k,v]) => [k, { label:v.label, passwordConfigured:Boolean(v.password), p12Configured:Boolean(v.p12Base64 || v.p12Path), profileConfigured:Boolean(v.provBase64 || v.provPath) }])) }));
app.listen(PORT, () => console.log(`Scarlet Direct Installing listening on ${PORT}; retention=${RETENTION_DAYS} days; R2=${r2Enabled}`));
