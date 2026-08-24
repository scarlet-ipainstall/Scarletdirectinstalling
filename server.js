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

app.set('trust proxy', 1);

const r2Enabled = Boolean(
  process.env.R2_ACCOUNT_ID &&
  process.env.R2_ACCESS_KEY_ID &&
  process.env.R2_SECRET_ACCESS_KEY &&
  process.env.R2_BUCKET_NAME &&
  process.env.R2_PUBLIC_BASE_URL
);

const r2 = r2Enabled ? new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID,
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
  }
}) : null;

await fs.mkdir(ROOT, { recursive: true });
app.use(express.static('public'));

function safeName(name) {
  return path.basename(name).replace(/[^a-zA-Z0-9._-]/g, '_');
}

function publicBase(req) {
  const configured = process.env.PUBLIC_BASE_URL?.trim();
  if (configured) return configured.replace(/\/$/, '').replace(/^http:\/\//i, 'https://');
  return `https://${req.get('host')}`;
}

function assertHttpsUrl(value, name) {
  if (!/^https:\/\//i.test(value)) throw new Error(`${name} must use HTTPS`);
}

async function put(key, data, contentType) {
  await r2.send(new PutObjectCommand({
    Bucket: process.env.R2_BUCKET_NAME,
    Key: key,
    Body: data,
    ContentType: contentType,
    CacheControl: 'public, max-age=31536000'
  }));
}

// Read the Bundle Identifier directly from the IPA. The signer no longer
// accepts a user-supplied Bundle ID or rewrites it with zsign -b.
async function getBundleIdFromIpa(ipaPath) {
  const script = `import glob, plistlib, sys, zipfile\nwith zipfile.ZipFile(sys.argv[1]) as z:\n    names=[n for n in z.namelist() if n.startswith('Payload/') and n.endswith('.app/Info.plist')]\n    if not names: raise SystemExit('Payload/*.app/Info.plist not found')\n    with z.open(names[0]) as f:\n        p=plistlib.load(f)\n    bid=p.get('CFBundleIdentifier')\n    if not isinstance(bid,str) or not bid: raise SystemExit('CFBundleIdentifier not found')\n    print(bid)`;
  const { stdout } = await exec('python3', ['-c', script, ipaPath], {
    timeout: 30 * 1000,
    maxBuffer: 256 * 1024
  });
  const bundleId = stdout.trim();
  if (!/^[A-Za-z0-9.-]+$/.test(bundleId)) throw new Error('Invalid Bundle ID in IPA.');
  return bundleId;
}

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

  if (!ipa || !p12 || !prov) {
    return res.status(400).json({ error: 'Upload an IPA, .p12 certificate, and .mobileprovision profile.' });
  }
  if (!password) return res.status(400).json({ error: 'A .p12 password is required.' });

  const id = crypto.randomBytes(8).toString('hex');
  const out = path.join(ROOT, `${id}-signed.ipa`);
  const appName = safeName(ipa.originalname).replace(/\.ipa$/i, '') || 'Signed App';
  const filename = `${appName}-signed.ipa`;

  try {
    const bundleId = await getBundleIdFromIpa(ipa.path);

    // Validate the supplied certificate/profile pair. This check is still
    // required by Apple's signing model; only the manual Bundle ID field was
    // removed. The IPA's existing Bundle ID is preserved during signing.
    try {
      await exec('zsign', ['-C', '-k', p12.path, '-p', password, '-m', prov.path], {
        timeout: 60 * 1000,
        maxBuffer: 2 * 1024 * 1024
      });
    } catch (checkError) {
      const detail = String(checkError.stderr || checkError.stdout || checkError.message).slice(0, 1500);
      return res.status(400).json({
        error: 'The Apple certificate/provisioning profile did not pass validation. Upload a valid certificate/profile pair authorized for this app.',
        bundleId,
        detail
      });
    }

    // Do not pass -b. This preserves the IPA's original Bundle ID instead of
    // forcing an unrelated value such as com.delta.bz.
    await exec('zsign', [
      '-f',
      '-k', p12.path,
      '-p', password,
      '-m', prov.path,
      '-r', version,
      '-o', out,
      ipa.path
    ], {
      timeout: 10 * 60 * 1000,
      maxBuffer: 2 * 1024 * 1024
    });

    const ipaData = await fs.readFile(out);
    const key = `builds/${id}/${filename}`;
    const base = publicBase(req);
    assertHttpsUrl(base, 'Public base URL');

    let download;
    if (r2Enabled) {
      const r2Base = process.env.R2_PUBLIC_BASE_URL.replace(/\/$/, '').replace(/^http:\/\//i, 'https://');
      assertHttpsUrl(r2Base, 'R2 public URL');
      await put(key, ipaData, 'application/octet-stream');
      download = `${r2Base}/${key}`;
    } else {
      await fs.copyFile(out, path.join(ROOT, `${id}.ipa`));
      download = `${base}/download/${id}`;
    }

    assertHttpsUrl(download, 'IPA download URL');

    const manifest = `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>${download}</string></dict></array><key>metadata</key><dict><key>bundle-identifier</key><string>${bundleId}</string><key>bundle-version</key><string>${version}</string><key>kind</key><string>software</string><key>title</key><string>${appName}</string></dict></dict></array></dict></plist>`;
    const manifestKey = `builds/${id}/manifest.plist`;

    if (r2Enabled) await put(manifestKey, Buffer.from(manifest), 'application/xml');

    builds.set(id, {
      file: path.join(ROOT, `${id}.ipa`),
      name: filename,
      manifest,
      key,
      persistent: r2Enabled
    });

    const manifestUrl = `${base}/manifest/${id}.plist`;
    assertHttpsUrl(manifestUrl, 'Manifest URL');

    res.json({
      id,
      bundleId,
      download,
      manifest: manifestUrl,
      install: `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`,
      persistent: r2Enabled
    });
  } catch (e) {
    res.status(500).json({
      error: 'Signing failed. Check that the certificate, password, provisioning profile, and app authorization are valid.',
      detail: String(e.stderr || e.message).slice(0, 1500)
    });
  } finally {
    for (const f of [ipa, p12, prov]) {
      if (f?.path) await fs.rm(f.path, { force: true }).catch(() => {});
    }
    await fs.rm(out, { force: true }).catch(() => {});
  }
});

app.get('/download/:id', async (req, res) => {
  const b = builds.get(req.params.id);
  if (!b || b.persistent) return res.status(404).send('This build is stored in persistent storage.');
  res.download(b.file, b.name);
});

app.get('/manifest/:id.plist', async (req, res) => {
  const id = req.params.id;
  if (r2Enabled) {
    try {
      const obj = await r2.send(new GetObjectCommand({
        Bucket: process.env.R2_BUCKET_NAME,
        Key: `builds/${id}/manifest.plist`
      }));
      res.type('application/xml').send(Buffer.from(await obj.Body.transformToByteArray()));
      return;
    } catch {}
  }
  const b = builds.get(id);
  if (!b) return res.status(404).send('Manifest not found.');
  res.type('application/xml').send(b.manifest);
});

app.get('/health', (_req, res) => res.json({ ok: true, persistentStorage: r2Enabled }));
app.listen(PORT, () => console.log(`Scarlet Direct Installing listening on ${PORT}`));
