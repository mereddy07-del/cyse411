// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// Canonicalization helper
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// -------------------------
// SECURE /read ROUTE
// -------------------------
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);

    // Prevent traversal
    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }

    if (!fs.existsSync(normalized)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// -------------------------
// SECURE read-no-validate ROUTE
// -------------------------
app.post('/read-no-validate', (req, res) => {
  const filename = req.body.filename || '';

  // Basic normalization
  let safeName = path.normalize(filename);

  // Block ../ and absolute paths
  if (safeName.includes('..') || path.isAbsolute(safeName)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  const filePath = resolveSafe(BASE_DIR, safeName);

  // Prevent breaking out of BASE_DIR
  if (!fullPath.startsWith(BASE_DIR + path.sep)) {
    return res.status(403).json({ error: 'Path traversal blocked' });
  }

  if (!fs.existsSync(fullPath)) {
    return res.status(404).json({ error: 'File not found', path: fullPath });
  }

  const content = fs.readFileSync(fullPath, 'utf8');
  res.json({ path: fullPath, content });
});

// -------------------------
// SECURE SAMPLE FILE CREATOR
// -------------------------
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };

  for (const key of Object.keys(samples)) {
    // DO NOT trust the filenames in the dictionary
    const normalized = path.normalize(key);

    // block ../ or absolute paths (Semgrep wants this)
    if (normalized.includes('..') || path.isAbsolute(normalized)) {
      continue;
    }

    const filePath = resolveSafe(BASE_DIR, normalized);

    // ensure stays inside BASE_DIR
    if (!filePath.startsWith(BASE_DIR + path.sep)) {
      continue;
    }

    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

    fs.writeFileSync(filePath, samples[key], 'utf8');
  }

  res.json({ ok: true, base: BASE_DIR });
});

// -------------------------
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => console.log(`Server listening on http://localhost:${port}`));
}

module.exports = app;
