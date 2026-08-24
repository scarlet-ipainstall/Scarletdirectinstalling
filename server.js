import express from 'express';
import multer from 'multer';
import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const exec = promisify(execFile);
const app = express();
const PORT = process.env.PORT || 10000;
const ROOT = '/tmp/scarlet';
const upload = multer({ dest: ROOT, limits: { fileSize: 1024 * 1024 * 1024, files: 3 } });
const builds = new Map();

const r2Enabled = process.env.R2_ACCOUNT_ID && process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY && process.env.R2_BUCKET_NAME;
const r2 = r2Enabled ? new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY }
}) : null;

await fs.mkdir(ROOT, { recursive: true });
app.use(express.static('public'));

function safeName(name) { return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_'); }
function publicBase(req) { return (process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get('host')}`).replace(/\/$/, ''); }

async function saveObject(key, data, contentType) {
  if (!r2) return false;
  await r2.send(new PutObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key, Body: data, ContentType: contentType }));
  return true;
}

async function getR2(key) {
  return r2.send(new GetObjectCommand({ Bucket: process.env.R2_BUCKET_NAME, Key: key }));
}

app.post('/api/sign', upload.fields([{ name: 'ipa', maxCount: 1 }, { name: 'p12', maxCount: 1 }, { name: 'mobileprovision', maxCount: 1 }]), async (req, res) => {
  const files = req.files || {};
  const ipa = files.ipa?.[0];
  const p12 = files.p12?.[0];
  const prov = files.mobileprovision?.[0];
  const password = String(req.body.password || '');
  if (!ipa || !p12 || !prov) return res.status(400).json({ error: 'Upload an IPA, .p12 certificate, and .mobileprovision profile.' });
  if (!password) return res.status(400).json({ error: 'A .p12 password is required.' });

  const id = crypto.randomBytes(8).toString('hex');
  const out = path.join(ROOT, `${id}-signed.ipa`);
  try {
    // User-provided credentials are used only for this signing job and are deleted afterwards.
    await exec('zsign', ['-f', '-k', p12.path, '-p', password, '-m', prov.path, '-o', out, ipa.path], { timeout: 10 * 60 * 1000, maxBuffer: 2 * 1024 * 1024 });
    const ipaData = await fs.readFile(out);
    const key = `builds/${id}/${safeName(ipa.originalname).replace(/\.ipa$/i, '')}-signed.ipa`;
    const stored = await saveObject(key, ipaData, 'application/octet-stream');
    builds.set(id, { key, file: out, name: `${safeName(ipa.originalname).replace(/\.ipa$/i, '')}-signed.ipa` });
    const base = publicBase(req);
    res.json({ id, download: stored ? `${process.env.R2_PUBLIC_BASE_URL.replace(/\/$/, '')}/${key}` : `${base}/download/${id}`, manifest: `${base}/manifest/${id}.plist`, install: `itms-services://?action=download-manifest&url=${encodeURIComponent(`${base}/manifest/${id}.plist`)}`, persistent: stored });
  } catch (e) {
    res.status(500).json({ error: 'Signing failed. Check that the certificate, password, and provisioning profile are valid.', detail: String(e.stderr || e.message).slice(0, 1000) });
  } finally {
    for (const f of [ipa, p12, prov]) if (f?.path) await fs.rm(f.path, { force: true }).catch(() => {});
    await fs.rm(out, { force: true }).catch(() => {});
  }
});

app.get('/download/:id', async (req, res) => {
  const b = builds.get(req.params.id);
  if (!b) return res.status(404).send('Build not found. Configure R2 for persistent storage.');
  res.download(b.file, b.name);
});

app.get('/manifest/:id.plist', async (req, res) => {
  const b = builds.get(req.params.id);
  const ipaUrl = r2 && process.env.R2_PUBLIC_BASE_URL ? `${process.env.R2_PUBLIC_BASE_URL.replace(/\/$/, '')}/${b?.key || `builds/${req.params.id}/signed.ipa`}` : `${publicBase(req)}/download/${req.params.id}`;
  if (!b && !r2) return res.status(404).send('Manifest not found.');
  const name = b?.name?.replace(/\.ipa$/i, '') || 'Signed App';
  const plist = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${ipaUrl}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${process.env.DEFAULT_BUNDLE_ID || 'com.example.app'}</string><key>bundle-version</key><string>1.0</string><key>kind</key><string>software</string><key>title</key><string>${name}</string></dict></dict></array></dict></plist>`;
  res.type('application/xml').send(plist);
});

app.get('/health', (_req, res) => res.json({ ok: true, persistentStorage: Boolean(r2) }));
app.listen(PORT, () => console.log(`Scarlet Direct Installing listening on ${PORT}`));
