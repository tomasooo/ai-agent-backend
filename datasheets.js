// datasheets.js
// RAG modul pro datasheety — chunking, embedding, vyhledávání
// Závislosti: openai, multer, pg (pool se předává zvenku)
// Instalace: npm install multer

import OpenAI from 'openai';
import multer from 'multer';
import path from 'path';
import fs from 'fs/promises';

const EMBEDDING_MODEL = 'text-embedding-3-small'; // nejlevnější, $0.02 / 1M tokenů
const CHUNK_SIZE = 500;       // slov na chunk
const CHUNK_OVERLAP = 50;     // překryv slov mezi chunky (lepší kontext)
const TOP_K = 3;              // kolik chunků vytáhneme do promptu

// ─── Multer — dočasné uložení souboru na disk ───────────────────────────────
const upload = multer({
  dest: '/tmp/datasheets/',
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB
  fileFilter: (_req, file, cb) => {
    const allowed = ['.pdf', '.docx', '.txt', '.xlsx', '.csv'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowed.includes(ext)) cb(null, true);
    else cb(new Error(`Nepodporovaný formát: ${ext}. Povolené: ${allowed.join(', ')}`));
  },
});

// ─── Extrakce textu ze souboru ───────────────────────────────────────────────
async function extractText(filePath, originalName) {
  const ext = path.extname(originalName).toLowerCase();

  if (ext === '.txt' || ext === '.csv') {
    return await fs.readFile(filePath, 'utf-8');
  }

  if (ext === '.pdf') {
    // Dynamický import — balík nemusí být nainstalovaný, fallback na varování
    try {
      const { default: pdfParse } = await import('pdf-parse/lib/pdf-parse.js');
      const buffer = await fs.readFile(filePath);
      const data = await pdfParse(buffer);
      return data.text;
    } catch {
      throw new Error('Pro PDF je potřeba npm install pdf-parse');
    }
  }

  if (ext === '.docx') {
    try {
      const { extractRawText } = await import('mammoth');
      const result = await extractRawText({ path: filePath });
      return result.value;
    } catch {
      throw new Error('Pro DOCX je potřeba npm install mammoth');
    }
  }

  if (ext === '.xlsx') {
    try {
      const XLSX = await import('xlsx');
      const wb = XLSX.readFile(filePath);
      return wb.SheetNames.map(name => {
        const ws = wb.Sheets[name];
        return `--- List: ${name} ---\n` + XLSX.utils.sheet_to_csv(ws);
      }).join('\n\n');
    } catch {
      throw new Error('Pro XLSX je potřeba npm install xlsx');
    }
  }

  throw new Error(`Nepodporovaný formát: ${ext}`);
}

// ─── Chunking — text → pole chunků ──────────────────────────────────────────
function chunkText(text) {
  // Normalizace bílých znaků
  const words = text.replace(/\s+/g, ' ').trim().split(' ');
  const chunks = [];
  let i = 0;

  while (i < words.length) {
    const slice = words.slice(i, i + CHUNK_SIZE);
    chunks.push(slice.join(' '));
    i += CHUNK_SIZE - CHUNK_OVERLAP;
    if (i >= words.length) break;
  }

  return chunks.filter(c => c.trim().length > 20); // vyhoď prázdné/krátké chunky
}

// ─── Embedding jednoho chunku ────────────────────────────────────────────────
async function embedText(openai, text) {
  const resp = await openai.embeddings.create({
    model: EMBEDDING_MODEL,
    input: text.slice(0, 8000), // max input pro model
  });
  return resp.data[0].embedding; // pole float čísel
}

// ─── Uložení datasheetu a jeho chunků do DB ──────────────────────────────────
export async function ingestDatasheet({ pool, openai, dashboardUserEmail, connectedEmail, originalName, filePath }) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // 1. Extrakce textu
    const text = await extractText(filePath, originalName);
    if (!text || text.trim().length < 10) throw new Error('Soubor neobsahuje žádný čitelný text.');

    // 2. Uložení záznamu datasheetu
    const dsRes = await client.query(
      `INSERT INTO datasheets (dashboard_user_email, connected_email, filename, char_count, created_at)
       VALUES ($1, $2, $3, $4, NOW())
       RETURNING id`,
      [dashboardUserEmail, connectedEmail, originalName, text.length]
    );
    const datasheetId = dsRes.rows[0].id;

    // 3. Chunking
    const chunks = chunkText(text);
    console.log(`[RAG] ${originalName}: ${chunks.length} chunků z ${text.length} znaků`);

    // 4. Embedding + uložení každého chunku
    for (let idx = 0; idx < chunks.length; idx++) {
      const chunk = chunks[idx];
      const vector = await embedText(openai, chunk);
      // pgvector očekává JSON pole čísel jako text: '[0.1, 0.2, ...]'
      await client.query(
        `INSERT INTO datasheet_chunks (datasheet_id, dashboard_user_email, connected_email, chunk_index, content, embedding)
         VALUES ($1, $2, $3, $4, $5, $6::vector)`,
        [datasheetId, dashboardUserEmail, connectedEmail, idx, chunk, JSON.stringify(vector)]
      );
    }

    await client.query('COMMIT');
    console.log(`[RAG] Ingested: ${originalName} (${chunks.length} chunků) pro ${dashboardUserEmail}`);
    return { datasheetId, chunkCount: chunks.length };

  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
    // Smaž dočasný soubor
    await fs.unlink(filePath).catch(() => {});
  }
}

// ─── Vyhledání relevantních chunků pro email ─────────────────────────────────
export async function retrieveRelevantChunks({ pool, openai, dashboardUserEmail, connectedEmail, query }) {
  // 1. Embedding dotazu (emailu)
  const queryVector = await embedText(openai, query.slice(0, 2000));

  // 2. Cosine similarity search v pgvector
  const res = await pool.query(
    `SELECT content, 1 - (embedding <=> $1::vector) AS similarity
       FROM datasheet_chunks
      WHERE dashboard_user_email = $2
        AND connected_email = $3
      ORDER BY embedding <=> $1::vector
      LIMIT $4`,
    [JSON.stringify(queryVector), dashboardUserEmail, connectedEmail, TOP_K]
  );

  // Vrať chunky nad prahem - pokud žádný neprojde, vrať stejně top výsledky
  // (fallback zajistí že datasheet se použije vždy když existuje)
  const filtered = res.rows.filter(r => r.similarity >= 0.1);
  if (filtered.length > 0) {
    return filtered.map(r => r.content);
  }
  // Fallback: žádný chunk nepřekročil práh - vrať top výsledky bez filtru
  return res.rows.map(r => r.content);
}

// ─── Sestavení kontextu pro prompt ───────────────────────────────────────────
export function buildDatasheetsContext(chunks) {
  if (!chunks || chunks.length === 0) return '';
  return (
    'ZNALOSTNÍ DATABÁZE (čerpej z ní při tvorbě odpovědi, pokud je relevantní):\n---\n' +
    chunks.join('\n\n---\n') +
    '\n---\n\n'
  );
}

// ─── Express route factory — zaregistruje /api/datasheets/* endpointy ────────
export function registerDatasheetsRoutes(app, pool, openai) {

  // POST /api/datasheets/upload
  app.post('/api/datasheets/upload', upload.single('file'), async (req, res) => {
    const { dashboardUserEmail, connectedEmail } = req.body || {};
    if (!dashboardUserEmail || !connectedEmail) {
      return res.status(400).json({ success: false, message: 'Chybí dashboardUserEmail nebo connectedEmail.' });
    }
    if (!req.file) {
      return res.status(400).json({ success: false, message: 'Soubor nebyl nahrán.' });
    }

    try {
      // Multer dekóduje název souboru jako Latin-1 — opravíme na UTF-8
      const originalName = Buffer.from(req.file.originalname, 'latin1').toString('utf8');

      const result = await ingestDatasheet({
        pool, openai,
        dashboardUserEmail,
        connectedEmail,
        originalName,
        filePath: req.file.path,
      });
      res.json({ success: true, ...result });
    } catch (err) {
      console.error('[RAG] Upload error:', err);
      // Smaž dočasný soubor i při chybě
      await fs.unlink(req.file.path).catch(() => {});
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // GET /api/datasheets?dashboardUserEmail=...&connectedEmail=...
  app.get('/api/datasheets', async (req, res) => {
    const { dashboardUserEmail, connectedEmail } = req.query || {};
    if (!dashboardUserEmail) return res.status(400).json({ success: false, message: 'Chybí dashboardUserEmail.' });

    try {
      const r = await pool.query(
        `SELECT d.id, d.filename, d.char_count, d.created_at,
                COUNT(c.id) AS chunk_count
           FROM datasheets d
           LEFT JOIN datasheet_chunks c ON c.datasheet_id = d.id
          WHERE d.dashboard_user_email = $1
            AND ($2::text IS NULL OR d.connected_email = $2)
          GROUP BY d.id
          ORDER BY d.created_at DESC`,
        [dashboardUserEmail, connectedEmail || null]
      );
      res.json({ success: true, datasheets: r.rows });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });

  // DELETE /api/datasheets/:id
  app.delete('/api/datasheets/:id', async (req, res) => {
    const { dashboardUserEmail } = req.query || {};
    const { id } = req.params;
    if (!dashboardUserEmail) return res.status(400).json({ success: false, message: 'Chybí dashboardUserEmail.' });

    try {
      // Chunky se smažou automaticky (CASCADE)
      const r = await pool.query(
        `DELETE FROM datasheets WHERE id = $1 AND dashboard_user_email = $2 RETURNING id`,
        [id, dashboardUserEmail]
      );
      if (r.rowCount === 0) return res.status(404).json({ success: false, message: 'Datasheet nenalezen.' });
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ success: false, message: err.message });
    }
  });
}

// ─── DB migrace — spusť jednou při startu serveru ────────────────────────────
export async function setupDatasheetsDB(pool) {
  const client = await pool.connect();
  try {
    // Aktivuj pgvector rozšíření (musí být povoleno v Postgres)
    await client.query(`CREATE EXTENSION IF NOT EXISTS vector`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS datasheets (
        id               SERIAL PRIMARY KEY,
        dashboard_user_email TEXT NOT NULL,
        connected_email  TEXT NOT NULL,
        filename         TEXT NOT NULL,
        char_count       INTEGER DEFAULT 0,
        created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS datasheet_chunks (
        id                   SERIAL PRIMARY KEY,
        datasheet_id         INTEGER NOT NULL REFERENCES datasheets(id) ON DELETE CASCADE,
        dashboard_user_email TEXT NOT NULL,
        connected_email      TEXT NOT NULL,
        chunk_index          INTEGER NOT NULL,
        content              TEXT NOT NULL,
        embedding            vector(1536),
        created_at           TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);

    // Index pro rychlé vektorové vyhledávání (IVFFlat — vhodné pro <1M chunků)
    await client.query(`
      CREATE INDEX IF NOT EXISTS datasheet_chunks_embedding_idx
        ON datasheet_chunks
        USING ivfflat (embedding vector_cosine_ops)
        WITH (lists = 100)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS datasheet_chunks_user_email_idx
        ON datasheet_chunks (dashboard_user_email, connected_email)
    `);

    console.log('[RAG] DB tabulky a indexy jsou připraveny.');
  } finally {
    client.release();
  }
}
