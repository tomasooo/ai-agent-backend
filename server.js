
// server.js-test
import express from 'express';
import cron from 'node-cron';
import cors from 'cors';
import { OAuth2Client } from 'google-auth-library';
import { Pool } from 'pg';
import { google } from 'googleapis';
import { VertexAI } from '@google-cloud/vertexai';
import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { ImapFlow } from 'imapflow';
import fetch from 'node-fetch';
import nodemailer from 'nodemailer';
import { simpleParser } from 'mailparser';
import { XMLParser } from 'fast-xml-parser';
import libmime from 'libmime';
import dns from 'dns';
const { decodeWords } = libmime;
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';



const app = express();

// --- CORS + JSON (jediná globální konfigurace, musí být před routami) ---
const ORIGINS = [
  'https://ai-agent-frontend-9nrf.onrender.com',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()) : []),
  ...(process.env.FRONTEND_URL ? [process.env.FRONTEND_URL] : []),
];




app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

const PORT = process.env.PORT || 3000;

// Načtení proměnných prostředíconst 
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;
const DATABASE_URL = process.env.DATABASE_URL;
const PROJECT_ID = process.env.GOOGLE_PROJECT_ID;
const LOCATION = 'us-central1';
const CRON_SECRET = process.env.CRON_SECRET;
console.log("DEBUG: Načtená DATABASE_URL je:", DATABASE_URL);
const SERVER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${SERVER_URL}/api/oauth/google/callback`;


const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// --- [NEW] globální handlery, aby proces nespadl na neodchycenou chybu ---
process.on('unhandledRejection', (reason) => {
  console.error('[UNHANDLED REJECTION]', reason);
});

process.on('uncaughtException', (err) => {
  console.error('[UNCAUGHT EXCEPTION]', err);
});


// --- IMAP helper: keepalive + delší timeout + bezpečné logování ---

function createImapClient({ host, port = 993, secure = true, auth, servername }) {
  const client = new ImapFlow({
    host,                           // sem může jít IPv4 adresa
    port: Number(port),
    secure: !!secure,               // true = přímé SSL (993)
    auth,
    tls: {
      servername: servername || host,  // SNI = původní hostname (kvůli certifikátu)
      rejectUnauthorized: false
    },
    keepalive: {
      interval: 3 * 60 * 1000,
      idle: true,
      forceNoop: true,
      timeout: 20 * 1000
    },
    socketTimeout: 60 * 1000         // 60 s na handshake (můžeš snížit na 20 s)
  });

  client.on('error', (err) => {
    console.error('[IMAP] client error:', err?.code || err?.message || err);
  });

  return client;
}





function unwrapImapError(e) {
  try {
    if (!e) return '(bez detailu)';
    // AggregateError
    if (e.name === 'AggregateError' && Array.isArray(e.errors)) {
      return e.errors.map(x => unwrapImapError(x)).filter(Boolean).join(' | ');
    }
    // Node chyby: code/cause
    const parts = [];
    if (e.code) parts.push(String(e.code));
    if (e.message) parts.push(String(e.message));
    if (!e.message && typeof e.toString === 'function') parts.push(String(e));
    if (e.cause && (e.cause.message || e.cause.code)) {
      parts.push(unwrapImapError(e.cause));
    }
    return parts.filter(Boolean).join(' – ') || '(bez detailu)';
  } catch {
    return '(bez detailu)';
  }
}

async function resolveAWithSNI(hostname) {
  try {
    // vem čistě IPv4 (A) – žádné AAAA
    const { address } = await dns.promises.lookup(hostname, { family: 4 });
    return { connectHost: address, servername: hostname };
  } catch {
    // když lookup selže, vrať hostname (pojede klasicky)
    return { connectHost: hostname, servername: hostname };
  }
}


const xmlParser = new XMLParser({ ignoreAttributes: false });

async function tryFetch(url) {
  try {
    const r = await fetch(url, { method: 'GET' });
    if (!r.ok) return null;
    const txt = await r.text();
    return txt;
  } catch { return null; }
}

function parseMozillaConfig(xmlText) {
  // Podle formátu https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
  const xml = xmlParser.parse(xmlText);
  const cfg = xml?.clientConfig?.emailProvider;
  if (!cfg) return null;

  const incoming = Array.isArray(cfg?.incomingServer) ? cfg.incomingServer : [cfg.incomingServer];
  const outgoing = Array.isArray(cfg?.outgoingServer) ? cfg.outgoingServer : [cfg.outgoingServer];

  const imap = incoming.find(s => s?.['@_type']?.toLowerCase() === 'imap');
  const smtp = outgoing.find(s => s?.['@_type']?.toLowerCase() === 'smtp');

  const mapSocket = (t='SSL') => {
    t = String(t).toUpperCase();
    // Thunderbird používá "SSL", "STARTTLS", "plain"
    if (t.includes('START')) return { secure: false, starttls: true };
    if (t.includes('SSL'))   return { secure: true,  starttls: false };
    return { secure: false, starttls: false };
  };

  const imapSock = mapSocket(imap?.socketType);
  const smtpSock = mapSocket(smtp?.socketType);

  return {
    imap: {
      host: imap?.hostname,
      port: Number(imap?.port || (imapSock.secure ? 993 : 143)),
      secure: !!imapSock.secure,
      starttls: !!imapSock.starttls,
      username: imap?.username || '%EMAILADDRESS%'
    },
    smtp: {
      host: smtp?.hostname,
      port: Number(smtp?.port || (smtpSock.secure ? 465 : 587)),
      secure: !!smtpSock.secure,
      starttls: !!smtpSock.starttls,
      username: smtp?.username || '%EMAILADDRESS%'
    }
  };
}

async function mozillaAutoconfig(domain) {
  // 1) https://autoconfig.<domain>/mail/config-v1.1.xml
  // 2) http://autoconfig.<domain>/mail/config-v1.1.xml
  // 3) https://<domain>/.well-known/autoconfig/mail/config-v1.1.xml
  const urls = [
    `https://autoconfig.${domain}/mail/config-v1.1.xml`,
    `http://autoconfig.${domain}/mail/config-v1.1.xml`,
    `https://${domain}/.well-known/autoconfig/mail/config-v1.1.xml`,
  ];
  for (const u of urls) {
    const txt = await tryFetch(u);
    if (!txt) continue;
    const parsed = parseMozillaConfig(txt);
    if (parsed) return parsed;
  }
  return null;
}

function hardcodedProvider(domain) {
  const d = domain.toLowerCase();
  // ⚠️ doplň si, co používáš nejčastěji
  if (d === 'gmail.com' || d.endsWith('.gmail.com')) {
    return {
      imap: { host: 'imap.gmail.com', port: 993, secure: true, starttls: false, username: '%EMAILADDRESS%' },
      smtp: { host: 'smtp.gmail.com', port: 465, secure: true, starttls: false, username: '%EMAILADDRESS%' }
    };
  }
  if (d === 'outlook.com' || d === 'hotmail.com' || d === 'live.com' || d === 'office365.com' || d === 'microsoft.com') {
    return {
      imap: { host: 'outlook.office365.com', port: 993, secure: true,  starttls: false, username: '%EMAILADDRESS%' },
      smtp: { host: 'smtp.office365.com',   port: 587, secure: false, starttls: true,  username: '%EMAILADDRESS%' }
    };
  }
  if (d === 'seznam.cz' || d.endsWith('.seznam.cz')) {
    return {
      imap: { host: 'imap.seznam.cz', port: 993, secure: true, starttls: false, username: '%EMAILADDRESS%' },
      smtp: { host: 'smtp.seznam.cz', port: 465, secure: true, starttls: false, username: '%EMAILADDRESS%' }
    };
  }
  if (d === 'centrum.cz' || d === 'volny.cz' || d === 'atlas.cz') {
    return {
      imap: { host: `imap.${d}`, port: 993, secure: true, starttls: false, username: '%EMAILADDRESS%' },
      smtp: { host: `smtp.${d}`, port: 465, secure: true, starttls: false, username: '%EMAILADDRESS%' }
    };
  }
  return null;
}

function guessByConvention(domain) {
  return {
    imap: { host: `imap.${domain}`, port: 993, secure: true,  starttls: false, username: '%EMAILADDRESS%' },
    smtp: { host: `smtp.${domain}`, port: 465, secure: true,  starttls: false, username: '%EMAILADDRESS%' },
    fallback: [
      { imap: { host: `mail.${domain}`, port: 993, secure: true,  starttls: false },
        smtp: { host: `mail.${domain}`, port: 465, secure: true,  starttls: false } },
      { imap: { host: `imap.${domain}`, port: 143, secure: false, starttls: true  },
        smtp: { host: `smtp.${domain}`, port: 587, secure: false, starttls: true  } }
    ]
  };
}


function matchProviderByMx(mxHost = '') {
  if (!mxHost) return null;

 if (mxHost.includes('cesky-hosting')) {
  return {
    imap: { host: 'mail.cesky-hosting.cz', port: 993, secure: true,  starttls: false },
    smtp: { host: 'smtp.cesky-hosting.cz', port: 465, secure: false, starttls: true  }
  };
}
  if (mxHost.includes('wedos')) {
    return {
      imap: { host: 'imap.wedos.net', port: 993, secure: true,  starttls: false },
      smtp: { host: 'smtp.wedos.net', port: 465, secure: true,  starttls: false }
    };
  }
  if (mxHost.includes('forpsi')) {
    return {
      imap: { host: 'imap.forpsi.com', port: 993, secure: true,  starttls: false },
      smtp: { host: 'smtp.forpsi.com', port: 465, secure: true,  starttls: false }
    };
  }
  if (mxHost.includes('active24')) {
    return {
      imap: { host: 'imap.active24.com', port: 993, secure: true,  starttls: false },
      smtp: { host: 'smtp.active24.com', port: 465, secure: true,  starttls: false }
    };
  }
  if (mxHost.includes('google.com')) {
    return {
      imap: { host: 'imap.gmail.com', port: 993, secure: true,  starttls: false },
      smtp: { host: 'smtp.gmail.com', port: 465, secure: true,  starttls: false }
    };
  }
  if (mxHost.includes('outlook.com') || mxHost.includes('office365.com') || mxHost.includes('protection.outlook.com')) {
    return {
      imap: { host: 'outlook.office365.com', port: 993, secure: true,  starttls: false },
      smtp: { host: 'smtp.office365.com',   port: 587, secure: false, starttls: true  }
    };
  }
  if (mxHost.includes('seznam.cz')) {
    return {
      imap: { host: 'imap.seznam.cz', port: 993, secure: true,  starttls: false },
      smtp: { host: 'smtp.seznam.cz', port: 465, secure: true,  starttls: false }
    };
  }
  return null;
}

async function guessByResolution(domain) {
  const pairs = [
    { imap: `imap.${domain}`, smtp: `smtp.${domain}`, imapPort: 993, smtpPort: 465, imapSSL: true,  smtpSSL: true  },
    { imap: `mail.${domain}`, smtp: `mail.${domain}`, imapPort: 993, smtpPort: 465, imapSSL: true,  smtpSSL: true  },
    { imap: domain,           smtp: domain,           imapPort: 993, smtpPort: 465, imapSSL: true,  smtpSSL: true  },
    { imap: `imap.${domain}`, smtp: `smtp.${domain}`, imapPort: 143, smtpPort: 587, imapSSL: false, smtpSSL: false, imapSTARTTLS: true, smtpSTARTTLS: true },
    { imap: `mail.${domain}`, smtp: `mail.${domain}`, imapPort: 143, smtpPort: 587, imapSSL: false, smtpSSL: false, imapSTARTTLS: true, smtpSTARTTLS: true },
  ];

  for (const p of pairs) {
    const okImap = await canResolve(p.imap);
    const okSmtp = await canResolve(p.smtp);
    if (okImap && okSmtp) {
      return {
        imap: { host: p.imap, port: p.imapPort, secure: !!p.imapSSL, starttls: !!p.imapSTARTTLS },
        smtp: { host: p.smtp, port: p.smtpPort, secure: !!p.smtpSSL, starttls: !!p.smtpSTARTTLS }
      };
    }
  }
  return null;
}

async function canResolve(host) {
  try { await dns.promises.lookup(host); return true; }
  catch { return false; }
}





async function discoverMailConfig(emailAddress) {
  const domain = String(emailAddress).split('@')[1];
  if (!domain) throw new Error('Neplatný e-mail');

  // 1) Mozilla autoconfig (Thunderbird styl)
  const m = await mozillaAutoconfig(domain);
  if (m) return m;

  // 2) Rychlý match podle domény
  const h = hardcodedProvider(domain);
  if (h) return h;

  // 2.5) Podle MX záznamů (poznáme poskytovatele)
  let mxHost = '';
  try {
    const mx = await dns.promises.resolveMx(domain);
    mxHost = (mx.sort((a,b)=>a.priority-b.priority)[0]?.exchange || '').toLowerCase();
  } catch {}

  const byMx = matchProviderByMx(mxHost);
  if (byMx) return byMx;

  // 3) Ověřené pokusy (DNS lookup) – imap./smtp., mail./mail., STARTTLS fallbacky
  const resolved = await guessByResolution(domain);
  if (resolved) return resolved;

  // 4) Nouzový odhad
  return guessByConvention(domain);
}





app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    cb(null, ORIGINS.includes(origin));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  credentials: false,
  optionsSuccessStatus: 204,
}));

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FRONTEND_URL || !DATABASE_URL || !PROJECT_ID || !CRON_SECRET) {
    console.error("Chyba: Chybí potřebné proměnné prostředí!");
    process.exit(1);
}
// Dekódování JSON klíče z proměnné prostředí
const vertex_ai = new VertexAI({project: PROJECT_ID, location: LOCATION});
const model = vertex_ai.getGenerativeModel({
    model: 'gemini-2.5-flash',
});





// Nastavení databázového spojení
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Nutné pro Render
});





// Funkce pro vytvoření tabulky, pokud neexistuje
async function setupDatabase() {
    let client;
    try {
        client = await pool.connect();

        // 1. Tabulka pro uživatele, kteří se přihlašují do naší aplikace
        await client.query(`
        CREATE TABLE IF NOT EXISTS dashboard_users (
            email VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255),
                plan VARCHAR(50) DEFAULT 'Starter',
                role TEXT DEFAULT 'user', -- PŘIDÁNO: role s výchozí hodnotou 'user'
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
  ALTER TABLE dashboard_users
    ADD COLUMN IF NOT EXISTS password_hash TEXT,
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS verification_token TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user';
`);

        // 2. Tabulka pro emaily, které si uživatelé připojí (původní "users")
        // PŘIDALI JSME dashboard_user_email, který je cizím klíčem
        await client.query(`
            CREATE TABLE IF NOT EXISTS connected_accounts (
                email VARCHAR(255) PRIMARY KEY,
                refresh_token TEXT NOT NULL,
                dashboard_user_email VARCHAR(255) NOT NULL,
                active BOOLEAN DEFAULT true,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE
            );
        `);

        await client.query(`
  DO $$ BEGIN
    BEGIN
      ALTER TABLE connected_accounts ADD COLUMN active BOOLEAN DEFAULT true;
    EXCEPTION WHEN duplicate_column THEN
      -- sloupec už existuje
      NULL;
    END;
  END $$;
`);
        
        


        // 3. Tabulka pro nastavení, nyní s vazbou na uživatele i připojený účet
        await client.query(`
            CREATE TABLE IF NOT EXISTS settings (
    dashboard_user_email VARCHAR(255) NOT NULL,
    connected_email VARCHAR(255) NOT NULL,
    tone VARCHAR(50) DEFAULT 'Formální',
    length VARCHAR(50) DEFAULT 'Střední (1 odstavec)',
    signature TEXT DEFAULT '',
    auto_reply BOOLEAN DEFAULT true,
    approval_required BOOLEAN DEFAULT true,
    spam_filter BOOLEAN DEFAULT true,
    PRIMARY KEY (dashboard_user_email, connected_email),
    FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE
    -- POZOR: žádný FK na connected_accounts, ať to funguje i pro custom účty
  );
        `);


      await client.query(`
  DO $$ BEGIN
    IF EXISTS (
      SELECT 1
      FROM information_schema.table_constraints tc
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_name = 'settings'
        AND tc.constraint_name = 'settings_connected_email_fkey'
    ) THEN
      ALTER TABLE settings DROP CONSTRAINT settings_connected_email_fkey;
    END IF;
  END $$;
`);

      await client.query(`
  CREATE TABLE IF NOT EXISTS custom_accounts (
    id SERIAL PRIMARY KEY,
    dashboard_user_email VARCHAR(255) NOT NULL REFERENCES dashboard_users(email) ON DELETE CASCADE,
    email_address VARCHAR(255) NOT NULL,
    imap_host TEXT NOT NULL,
    imap_port INT NOT NULL,
    imap_secure BOOLEAN NOT NULL DEFAULT true,
    smtp_host TEXT NOT NULL,
    smtp_port INT NOT NULL,
    smtp_secure BOOLEAN NOT NULL DEFAULT true,
    enc_username TEXT NOT NULL,
    enc_password TEXT NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (dashboard_user_email, email_address)
  );
`);

await client.query(`
  CREATE TABLE IF NOT EXISTS plans (
    code VARCHAR(50) PRIMARY KEY,
    label VARCHAR(100) NOT NULL,
    max_accounts INT NOT NULL,
    monthly_ai_actions INT NOT NULL
  );
`);

await client.query(`
  CREATE TABLE IF NOT EXISTS style_profiles (
    dashboard_user_email TEXT NOT NULL,
    connected_email TEXT,
    profile_json JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (dashboard_user_email, connected_email)
  );
`);


await client.query(`
  CREATE TABLE IF NOT EXISTS faqs (
    id BIGSERIAL PRIMARY KEY,
    dashboard_user_email TEXT NOT NULL,
    connected_email TEXT NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    source JSONB DEFAULT '[]'::jsonb, -- můžeš si sem ukládat odkazy na zprávy
    updated_at TIMESTAMPTZ DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS faqs_user_account_idx
    ON faqs(dashboard_user_email, connected_email);
`);
      
        

// 5) Seed základních plánů (lze kdykoli změnit v DB)
await client.query(`
  INSERT INTO plans (code, label, max_accounts, monthly_ai_actions) VALUES
    ('Starter','Starter', 1, 50),
    ('Professional','Professional', 5, 1000),
    ('Enterprise','Enterprise', 999, 100000)
  ON CONFLICT (code) DO NOTHING;
`);

// 6) Měsíční čítač použití AI
await client.query(`
  CREATE TABLE IF NOT EXISTS usage_counters (
    dashboard_user_email VARCHAR(255) NOT NULL,
    period_start DATE NOT NULL,                  -- první den měsíce (UTC)
    ai_actions_used INT NOT NULL DEFAULT 0,      -- počet provedených AI akcí v období
    PRIMARY KEY (dashboard_user_email, period_start),
    FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE
  );
`);

        await client.query(`
  CREATE TABLE IF NOT EXISTS templates (
    id SERIAL PRIMARY KEY,
    dashboard_user_email VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) DEFAULT 'Obecné',
    content TEXT NOT NULL,
    uses INT DEFAULT 0,
    success_rate NUMERIC(5,2) DEFAULT 0.00,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE
  );
`);

await client.query(`
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ DEFAULT NOW(),
                user_email VARCHAR(255),
                action TEXT NOT NULL,
                status VARCHAR(50) NOT NULL, -- 'success', 'error', 'info'
                details JSONB
            );
        `);

      
        
        console.log("✅ Databázové tabulky pro víceuživatelský provoz jsou připraveny.");
    } catch (err) {
        console.error('Chyba při nastavování databází:', err);
    } finally {
        if (client) {
            client.release();
        }
    }
}


// ---------- Helpers pro čtení Gmail zpráv ----------
function b64urlDecode(data = '') {
  if (!data) return '';
  const n = data.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(n, 'base64').toString('utf-8');
}

function extractPlainText(payload) {
  if (!payload) return '';
  // 1) přednostně text/plain
  if (payload.mimeType === 'text/plain' && payload.body?.data) {
    return b64urlDecode(payload.body.data);
  }
  // 2) multipart? projdi části
  if (payload.parts && Array.isArray(payload.parts)) {
    // zkus najít nejdřív text/plain
    for (const p of payload.parts) {
      const t = extractPlainText(p);
      if (t) return t;
    }
  }
  // 3) fallback: text/html -> ořež tagy
  if (payload.mimeType === 'text/html' && payload.body?.data) {
    const html = b64urlDecode(payload.body.data);
    return html.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').trim();
  }
  // 4) fallback na body.data bez ohledu na typ
  if (payload.body?.data) return b64urlDecode(payload.body.data);
  return '';
}





async function getGmailClientFor(dashboardUserEmail, email) {
  const db = await pool.connect();
  try {
    const r = await db.query(
      'SELECT refresh_token FROM connected_accounts WHERE email=$1 AND dashboard_user_email=$2',
      [email, dashboardUserEmail]
    );
    const refreshToken = r.rows[0]?.refresh_token;
    if (!refreshToken) throw new Error('Refresh token nenalezen');
    oauth2Client.setCredentials({ refresh_token: refreshToken });
    return google.gmail({ version: 'v1', auth: oauth2Client });
  } finally {
    db.release();
  }
}


async function logActivity(user_email, action, status, details = {}) {
    let client;
    try {
        client = await pool.connect();
        await client.query(
            'INSERT INTO audit_log (user_email, action, status, details) VALUES ($1, $2, $3, $4)',
            [user_email, action, status, details]
        );
    } catch (e) {
        console.error('Chyba při zápisu do audit_log:', e);
    } finally {
        if (client) client.release();
    }
}


app.get('/api/gmail/sent-replies', async (req, res) => {
 try {
    const { dashboardUserEmail, email, limit = 200 } = req.query;
    if (!dashboardUserEmail || !email) {
      return res.status(400).json({ success:false, message:'Chybí parametry.' });
    }

    let gmail;
    try {
      gmail = await getGmailClientFor(dashboardUserEmail, email);
    } catch (e) {
      return sendGmailApiError(res, e, 'SENT');
    }

    const list = await gmail.users.messages.list({
      userId: 'me',
      labelIds: ['SENT'],
      includeSpamTrash: false,
      maxResults: Math.min(Number(limit) || 200, 500),
    });

    const ids = (list.data?.messages || []).map(m => m.id);
    if (!ids.length) return res.json({ success:true, items: [] });

    const items = [];
    for (const id of ids) {
      try {
        const msg = await gmail.users.messages.get({ userId: 'me', id });
        const payload = msg.data?.payload;
        const headers = payload?.headers || [];
        const subject = headers.find(h => h.name === 'Subject')?.value || '';
        const body = extractPlainText(payload);
        if (body) items.push({ role:'outgoing', subject, body });
      } catch (e) {
        console.warn('[SENT] skip message', id, e?.message || e);
        continue;
      }
    }

    return res.json({ success:true, items });
  } catch (e) {
    return sendGmailApiError(res, e, 'SENT');
  }
});




function extractEmail(s = '') {
  const m = String(s).match(/<([^>]+)>/);   // "Jméno <mail@domena>" -> "mail@domena"
  const raw = m ? m[1] : String(s);
  return raw.trim().replace(/^mailto:/i, '');
}

function decodeHeader(str = '') {
  try {
    return decodeWords(str);
  } catch {
    return str;
  }
}



async function resolveIPv4(host) {
  try {
    const { address } = await dns.promises.lookup(host, { family: 4 });
    return address; // vrátíme IPv4 adresu
  } catch {
    return host;   // když lookup selže, necháme původní hostname
  }
}



app.post('/api/custom-email/connect', async (req, res) => {
  const {
    dashboardUserEmail,
    emailAddress,
    password
  } = req.body || {};

  if (!dashboardUserEmail || !emailAddress || !password) {
    return res.status(400).json({ success:false, message:'Zadej e-mail a heslo.' });
  }

  // username defaultně = celý e-mail
  const baseUsername = (req.body?.username || emailAddress).trim();

  // pokud nejsou IMAP/SMTP údaje, pokusíme se je zjistit
  let imapHost = req.body?.imapHost;
  let imapPort = req.body?.imapPort;
  let imapSecure = req.body?.imapSecure;
  let smtpHost = req.body?.smtpHost;
  let smtpPort = req.body?.smtpPort;
  let smtpSecure = req.body?.smtpSecure;
  let starttlsImap = false;
  let starttlsSmtp = false;

  if (!imapHost || !smtpHost) {
    try {
      const discovered = await discoverMailConfig(emailAddress);

      imapHost   = imapHost   || discovered.imap.host;
      imapPort   = Number(imapPort ?? discovered.imap.port);
      imapSecure = (imapSecure ?? discovered.imap.secure) ? true : false;
      starttlsImap = !!discovered.imap.starttls;

      smtpHost   = smtpHost   || discovered.smtp.host;
      smtpPort   = Number(smtpPort ?? discovered.smtp.port);
      smtpSecure = (smtpSecure ?? discovered.smtp.secure) ? true : false;
      starttlsSmtp = !!discovered.smtp.starttls;
    } catch (e) {
      return res.status(400).json({ success:false, message:'Automatické zjištění nastavení selhalo: ' + (e?.message || e) });
    }
  }
// 1) Ověřit IMAP přihlášení – preferuj IPv4 + 993/SSL, pak 143/STARTTLS
const { connectHost, servername } = await resolveAWithSNI(imapHost);

const imapAttempts = [
  // 993/SSL (přes IPv4)
  { host: connectHost, port: 993, secure: true,  servername },
  // 993/SSL (přes hostname, kdyby A-lookup selhal)
  { host: imapHost,    port: 993, secure: true,  servername },

  // 143/STARTTLS (přes IPv4)
  { host: connectHost, port: 143, secure: false, servername },
  // 143/STARTTLS (přes hostname)
  { host: imapHost,    port: 143, secure: false, servername },
];

let imapOk = false;
let imapLastErr = null;
const tried = new Set();

for (const a of imapAttempts) {
  const key = `${a.host}|${a.port}|${a.secure}`;
  if (tried.has(key)) continue;
  tried.add(key);

  const imapClient = createImapClient({
    host: a.host,
    port: a.port,
    secure: a.secure,
    servername: a.servername,
    auth: { user: baseUsername, pass: password }
  });

  // zkraťme handshake timeout, ať to nečeká věčnost
  imapClient.socketTimeout = 20000; // 20 s

  try {
    await imapClient.connect();
    await imapClient.logout().catch(()=>{});
    imapOk = true;

    // ulož do DB hostname (ne IP), jen port/zabezpečení aktualizuj
    imapPort = a.port;
    imapSecure = a.secure;
    break;
  } catch (e) {
    imapLastErr = e;
    console.warn('[IMAP verify failed]', a, unwrapImapError ? unwrapImapError(e) : (e?.message || e));
    try { if (imapClient?.connected) await imapClient.logout(); } catch {}
  }
}

if (!imapOk) {
  return res.status(400).json({
    success: false,
    message: 'IMAP přihlášení selhalo: ' + (unwrapImapError ? unwrapImapError(imapLastErr) : (imapLastErr?.message || imapLastErr))
  });
}


 

  // 2) Ověřit SMTP přihlášení
  try {
    const transporter = nodemailer.createTransport({
      host: smtpHost,
      port: Number(smtpPort),
      secure: !!smtpSecure,                // SSL/TLS (465)
      requireTLS: !!starttlsSmtp,           // STARTTLS (587)
      tls: { rejectUnauthorized: false },   // některé servery mají vlastní cert
      auth: { user: baseUsername, pass: password }
    });
    await transporter.verify();
  } catch (e) {
    return res.status(400).json({ success:false, message:'SMTP ověření selhalo: ' + (e?.message || e) });
  }

  // 3) Uložit šifrovaně do DB
  const db = await pool.connect();
  try {
    await db.query(`
      INSERT INTO custom_accounts
        (dashboard_user_email, email_address, imap_host, imap_port, imap_secure, smtp_host, smtp_port, smtp_secure, enc_username, enc_password, active)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,true)
      ON CONFLICT (dashboard_user_email, email_address) DO UPDATE
      SET imap_host=$3, imap_port=$4, imap_secure=$5,
          smtp_host=$6, smtp_port=$7, smtp_secure=$8,
          enc_username=$9, enc_password=$10, active=true
    `, [
      dashboardUserEmail, emailAddress,
      imapHost, Number(imapPort), !!imapSecure,
      smtpHost, Number(smtpPort), !!smtpSecure,
      encSecret(baseUsername), encSecret(password)
    ]);

    return res.json({ success:true, message:'Účet připojen.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success:false, message:'Uložení účtu selhalo.' });
  } finally {
    db.release();
  }
});




app.post('/api/custom-email/disconnect', async (req, res) => {
  const { dashboardUserEmail, emailAddress } = req.body || {};

  if (!dashboardUserEmail || !emailAddress) {
    return res.status(400).json({ success:false, message:'Chybí e-mail uživatele nebo účet.' });
  }

  const db = await pool.connect();
  try {
    const result = await db.query(
      `DELETE FROM custom_accounts WHERE dashboard_user_email=$1 AND email_address=$2`,
      [dashboardUserEmail, emailAddress]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success:false, message:'Účet nenalezen.' });
    }

    return res.json({ success:true, message:'Účet byl odstraněn.' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success:false, message:'Mazání účtu selhalo.' });
  } finally {
    db.release();
  }
});








app.get('/api/custom-email/emails', async (req, res) => {
  const { dashboardUserEmail, emailAddress, limit = 20 } = req.query || {};
  if (!dashboardUserEmail || !emailAddress) {
    return res.status(400).json({ success:false, message:'Chybí dashboardUserEmail nebo emailAddress.' });
  }

  const db = await pool.connect();
  let imap;
  try {
    const r = await db.query(`
      SELECT imap_host, imap_port, imap_secure, enc_username, enc_password
      FROM custom_accounts
      WHERE dashboard_user_email=$1 AND email_address=$2 AND active=true
      LIMIT 1
    `, [dashboardUserEmail, emailAddress]);

    if (!r.rowCount) return res.status(404).json({ success:false, message:'Custom účet nenalezen.' });

    const user = decSecret(r.rows[0].enc_username);
    const pass = decSecret(r.rows[0].enc_password);

    imap = createImapClient({
      host: r.rows[0].imap_host,
      port: Number(r.rows[0].imap_port),
      secure: !!r.rows[0].imap_secure,
      auth: { user, pass }
    });

    await imap.connect();

    // otevři INBOX a při selhání zkus alternativní názvy
    const tryOpen = async (name) => { try { await imap.mailboxOpen(name); return true; } catch { return false; } };
    if (!(await tryOpen('INBOX'))) {
      const fallbacks = ['Inbox', 'Doručená pošta', 'Doručená', 'Posteingang'];
      let opened = false;
      for (const f of fallbacks) { if (await tryOpen(f)) { opened = true; break; } }
      if (!opened) return res.status(404).json({ success:false, message:'Nepodařilo se otevřít schránku INBOX.' });
    }

    const out = [];
    const max = Math.min(Number(limit) || 20, 200);
    const startSeq = Math.max(1, (imap.mailbox?.exists || 1) - 500);

    // ⬅️ DŮLEŽITÉ: ŽÁDNÝ filtr "seen:false" – bereme i přečtené zprávy
    for await (const msg of imap.fetch(
      { seq: `${startSeq}:*` },
      { uid: true, envelope: true, internalDate: true, flags: true }
    )) {
      const fromRaw = msg.envelope?.from?.[0] || {};
      out.push({
        id: String(msg.uid), // sjednocený název pole
        uid: msg.uid,
        subject: decodeHeader(msg.envelope?.subject || ''),
        sender: (fromRaw.address || '').trim(),
        from: `${decodeHeader(fromRaw.name || '')} <${fromRaw.address || ''}>`,
        date: msg.internalDate ? msg.internalDate.toISOString() : null
      });
      if (out.length >= max) break;
    }

    // seřadit od nejnovějších (pro jistotu)
    out.sort((a, b) => (new Date(b.date || 0)) - (new Date(a.date || 0)));

    await imap.logout();
    return res.json({ success:true, emails: out, total: out.length });
  } catch (e) {
    console.error("Chyba IMAP:", e);
    try { if (imap?.connected) await imap.logout(); } catch {}
    return res.status(500).json({ success:false, message:'Nepodařilo se načíst emaily (custom).' });
  } finally {
    db.release();
  }
});

app.get('/api/gmail/inbox-examples', async (req, res) => {
 try {
    const { dashboardUserEmail, email, limit = 200 } = req.query;
    if (!dashboardUserEmail || !email) {
      return res.status(400).json({ success:false, message:'Chybí parametry.' });
    }

    let gmail;
    try {
      gmail = await getGmailClientFor(dashboardUserEmail, email);
    } catch (e) {
      return sendGmailApiError(res, e, 'INBOX');
    }

    const list = await gmail.users.messages.list({
      userId: 'me',
      labelIds: ['INBOX'],
      includeSpamTrash: false,
      q: '-from:me -in:spam -in:trash',
      maxResults: Math.min(Number(limit) || 200, 500),
    });

    const ids = (list.data?.messages || []).map(m => m.id);
    if (!ids.length) return res.json({ success:true, items: [] });

    const items = [];
    for (const id of ids) {
      try {
        const msg = await gmail.users.messages.get({ userId: 'me', id });
        const payload = msg.data?.payload;
        const headers = payload?.headers || [];
        const subject = headers.find(h => h.name === 'Subject')?.value || '';
        const fromHdr = headers.find(h => h.name === 'From')?.value || '';
        const from = decodeHeader(fromHdr);
        const body = extractPlainText(payload);
        if (body) items.push({ role:'incoming', subject, from, body });
      } catch (e) {
        // u jedné zprávy spadlo? pokračuj dál
        console.warn('[INBOX] skip message', id, e?.message || e);
        continue;
      }
    }

    return res.json({ success:true, items });
  } catch (e) {
    return sendGmailApiError(res, e, 'INBOX');
  }
});

// Jednorázově si někde spusť create table (např. při startu):
async function ensureStyleTables() {
  const db = await pool.connect();
  try {
    await db.query(`
      CREATE TABLE IF NOT EXISTS style_examples (
        id BIGSERIAL PRIMARY KEY,
        dashboard_user_email TEXT NOT NULL,
        connected_email TEXT NOT NULL,
        role TEXT CHECK (role IN ('incoming','outgoing')) NOT NULL,
        subject TEXT,
        body TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      );
    `);
  } finally { db.release(); }
}
ensureStyleTables().catch(console.error);

// === ANALYTICS: denní aktivita z tabulky style_examples ===
app.get('/api/analytics/activity', async (req, res) => {
  const { dashboardUserEmail, email, days = '7' } = req.query || {};
  const nDays = Math.min(parseInt(days, 10) || 7, 180);
  if (!dashboardUserEmail || !email) {
    return res.status(400).json({ success:false, message:'Chybí parametry.' });
  }
  const db = await pool.connect();
  try {
    const q = await db.query(`
      SELECT (created_at AT TIME ZONE 'Europe/Prague')::date AS day,
             COUNT(*) FILTER (WHERE role='incoming') AS incoming,
             COUNT(*) FILTER (WHERE role='outgoing') AS outgoing
        FROM style_examples
       WHERE dashboard_user_email = $1
         AND connected_email      = $2
         AND created_at >= NOW() - ($3 || ' days')::interval
       GROUP BY 1
       ORDER BY 1
    `, [dashboardUserEmail, email, nDays]);
    res.json({ success:true, days:nDays, series:q.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Analytics: activity selhala.' });
  } finally { db.release(); }
});

// === ANALYTICS: šablony – souhrn + TOP seznam ===
app.get('/api/analytics/templates', async (req, res) => {
  const { dashboardUserEmail } = req.query || {};
  if (!dashboardUserEmail) {
    return res.status(400).json({ success:false, message:'Chybí dashboardUserEmail.' });
  }
  const db = await pool.connect();
  try {
    const totals = await db.query(`
      SELECT COUNT(*)::int                              AS total_templates,
             COALESCE(SUM(uses),0)::int                 AS total_uses,
             ROUND(AVG(NULLIF(success_rate,0))::numeric, 2) AS avg_success_rate
        FROM templates
       WHERE dashboard_user_email = $1
    `, [dashboardUserEmail]);

    const top = await db.query(`
      SELECT name,
             COALESCE(uses,0)::int        AS uses,
             COALESCE(success_rate,0)::float AS success_rate,
             category
        FROM templates
       WHERE dashboard_user_email = $1
       ORDER BY uses DESC NULLS LAST, updated_at DESC
       LIMIT 10
    `, [dashboardUserEmail]);

    res.json({ success:true, ...totals.rows[0], top: top.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Analytics: templates selhala.' });
  } finally { db.release(); }
});

// === ANALYTICS: kategorie – koláč podle uses v tabulce templates ===
app.get('/api/analytics/categories', async (req, res) => {
  const { dashboardUserEmail } = req.query || {};
  if (!dashboardUserEmail) {
    return res.status(400).json({ success:false, message:'Chybí dashboardUserEmail.' });
  }
  const db = await pool.connect();
  try {
    const r = await db.query(`
      SELECT COALESCE(category, 'Nezařazené') AS category,
             SUM(COALESCE(uses,0))::int       AS uses
        FROM templates
       WHERE dashboard_user_email = $1
       GROUP BY 1
       ORDER BY 2 DESC
    `, [dashboardUserEmail]);
    res.json({ success:true, items:r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Analytics: categories selhala.' });
  } finally { db.release(); }
});



app.post('/api/style-examples/ingest', async (req, res) => {
  try {
    const { dashboardUserEmail, email, items } = req.body || {};
    if (!dashboardUserEmail || !email || !Array.isArray(items)) {
      return res.status(400).json({ success:false, message:'Chybí data.' });
    }

    const trimmed = items
      .filter(x => x && (x.body || '').trim())
      .slice(0, 1000); // pojistka

    if (!trimmed.length) {
      return res.json({ success:true, saved: 0 });
    }

    const db = await pool.connect();
    try {
      const text = `
        INSERT INTO style_examples (dashboard_user_email, connected_email, role, subject, body)
        VALUES ($1,$2,$3,$4,$5)
      `;
      for (const it of trimmed) {
        const role = (it.role === 'incoming' ? 'incoming' : 'outgoing');
        await db.query(text, [
          dashboardUserEmail,
          email,
          role,
          it.subject || '',
          it.body || ''
        ]);
      }
    } finally { db.release(); }

    return res.json({ success:true, saved: trimmed.length });
  } catch (e) {
    console.error('ingest error', e);
    return res.status(500).json({ success:false, message:'Chyba při ukládání příkladů' });
  }
});




function parseEncKey() {
  const raw = process.env.CUSTOM_EMAIL_KEY || '';
  if (!raw) throw new Error('CUSTOM_EMAIL_KEY is missing');

  // 64 hex znaků = 32 bytů
  if (/^[0-9a-fA-F]{64}$/.test(raw)) return Buffer.from(raw, 'hex');

  // base64 (doplníme padding)
  const looksBase64 = /^[A-Za-z0-9+/]+={0,2}$/.test(raw);
  if (looksBase64) return Buffer.from(raw, 'base64');

  // fallback: oříznout/napadovat na 32B
  const buf = Buffer.from(raw);
  if (buf.length >= 32) return buf.subarray(0,32);
  const out = Buffer.alloc(32);
  buf.copy(out);
  return out;
}
const ENC_KEY = parseEncKey(); // Buffer o délce 32

function encSecret(plain='') {
  if (!plain) return '';
  const iv = crypto.randomBytes(12); // GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString('base64');
}
function decSecret(b64='') {
  if (!b64) return '';
  const raw = Buffer.from(b64, 'base64');
  const iv = raw.subarray(0,12);
  const tag = raw.subarray(12,28);
  const data = raw.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
}





// Klient pro ověření PŘIHLAŠOVACÍHO tokenu (zůstává)
const loginClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// === CHYBĚJÍCÍ ČÁST: Klient pro PROPOJENÍ a ODPOJENÍ účtu ===
// Tento klient potřebuje i Client Secret a Redirect URI
const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI);
// ==========================================================





// ENDPOINT PRO PŘIHLÁŠENÍ
app.post('/api/auth/google', async (req, res) => {
    let client;
    try {
        const { token } = req.body;
        const ticket = await loginClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();

        client = await pool.connect();
        // Vytvoříme uživatele, pokud neexistuje (s výchozí rolí 'user')
        await client.query(
            `INSERT INTO dashboard_users (email, name, plan, role)
             VALUES ($1, $2, 'Starter', 'user')
             ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name`,
            [payload.email, payload.name]
        );
        
        // NOVĚ: Načteme kompletního uživatele z databáze, abychom získali jeho roli
        const userResult = await client.query(
            'SELECT email, name, plan, role FROM dashboard_users WHERE email = $1',
            [payload.email]
        );

        res.status(200).json({ success: true, user: userResult.rows[0] });
    } catch (error) {
        console.error("Chyba při ověřování přihlašovacího tokenu:", error);
        res.status(401).json({ success: false, message: 'Ověření selhalo.' });
    } finally {
        if (client) client.release();
    }
});






app.get('/api/style/get', async (req,res) => {
  const { dashboardUserEmail, email } = req.query;
  const style_profile = await loadStyleProfile({ dashboardUserEmail, email });
  res.json({ success:true, style_profile: style_profile || null });
});


// === LEARNING ENDPOINT (pro starý FE, co volá /api/style/learn) ===
app.post('/api/style/learn', async (req, res) => {
  try {
    const { dashboardUserEmail, email, limit = 200 } = req.body || req.query || {};
    if (!dashboardUserEmail || !email) {
      return res.status(400).json({ success:false, message:'Chybí dashboardUserEmail nebo email.' });
    }

    const gmail = await getGmailClientFor(dashboardUserEmail, email);
    const max = Math.min(Number(limit) || 200, 500);

    // načti seznamy zpráv
    const [sentList, inboxList] = await Promise.all([
      gmail.users.messages.list({ userId: 'me', labelIds: ['SENT'],  maxResults: max }),
      gmail.users.messages.list({ userId: 'me', labelIds: ['INBOX'], q: '-from:me -in:spam -in:trash', maxResults: max }),
    ]);

    // helper na stažení obsahu jednotlivých zpráv
    const loadItems = async (msgs = [], role = 'incoming') => {
      const out = [];
      for (const m of (msgs || [])) {
        const msg = await gmail.users.messages.get({ userId: 'me', id: m.id });
        const payload = msg.data.payload;
        const headers = payload?.headers || [];
        const subject = headers.find(h => h.name === 'Subject')?.value || '';
        const body = extractPlainText(payload);
        if (body) out.push({ role, subject, body });
      }
      return out;
    };

    const sentItems  = await loadItems(sentList.data.messages,  'outgoing');
    const inboxItems = await loadItems(inboxList.data.messages, 'incoming');
    const items = [...sentItems, ...inboxItems];

    // ulož do DB
    if (!items.length) return res.json({ success:true, saved: 0 });

    const db = await pool.connect();
    try {
      const sql = `
        INSERT INTO style_examples (dashboard_user_email, connected_email, role, subject, body)
        VALUES ($1,$2,$3,$4,$5)
      `;
      for (const it of items) {
        await db.query(sql, [dashboardUserEmail, email, it.role, it.subject || '', it.body || '']);
      }
    } finally {
      db.release();
    }

    return res.json({ success:true, saved: items.length });
  } catch (e) {
    console.error('[/api/style/learn] error', e);
    return res.status(500).json({ success:false, message:'Učení z historie selhalo.' });
  }
});



app.post('/api/faq/save', async (req, res) => {
  const { dashboardUserEmail, email, items } = req.body || {};
  if (!dashboardUserEmail || !email || !Array.isArray(items)) {
    return res.status(400).json({ success:false, message:'Chybí data.' });
  }
  const db = await pool.connect();
  try {
    await db.query(`DELETE FROM faqs WHERE dashboard_user_email=$1 AND connected_email=$2`, [dashboardUserEmail, email]);
    for (const it of items) {
      const q = (it.q || it.question || '').trim();
      const a = (it.a || it.answer   || '').trim();
      if (!q && !a) continue;
      await db.query(
        `INSERT INTO faqs (dashboard_user_email, connected_email, question, answer)
         VALUES ($1,$2,$3,$4)`,
        [dashboardUserEmail, email, q, a]
      );
    }
    res.json({ success:true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Uložení FAQ selhalo.' });
  } finally { db.release(); }
});


app.get('/api/auth/has-password', async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ success: false, message: 'Chybí email.' });

  const client = await pool.connect();
  try {
    const r = await client.query('SELECT password_hash IS NOT NULL AS has_password FROM dashboard_users WHERE email=$1', [email]);
    if (r.rowCount === 0) return res.json({ success: true, hasPassword: false });
    return res.json({ success: true, hasPassword: !!r.rows[0].has_password });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false, message: 'Chyba dotazu.' });
  } finally {
    client.release();
  }
});


async function loadStyleProfile({ dashboardUserEmail, email }) {
  const db = await pool.connect();
  try {
    const r = await db.query(
      `SELECT profile_json
         FROM style_profiles
        WHERE dashboard_user_email = $1
          AND (connected_email = $2 OR $2 IS NULL)
        LIMIT 1`,
      [dashboardUserEmail, email || null]
    );
    return r.rowCount ? r.rows[0].profile_json : null;
  } finally {
    db.release();
  }
}


app.get('/api/style-profile', async (req, res) => {
  const { dashboardUserEmail, email, debug } = req.query || {};
  if (!dashboardUserEmail || !email) {
    return res.status(400).json({ success:false, message:'Chybí parametry (dashboardUserEmail, email).' });
  }

  let client;
  try {
    client = await pool.connect();

    // 1) Ověř, že tabulka existuje
    const t = await client.query(`
      SELECT to_regclass('public.style_examples') AS exists
    `);
    if (!t.rows[0].exists) {
      return res.status(200).json({
        success: true,
        message: 'Tabulka style_examples neexistuje – spusť SQL migraci (viz níže).',
        profile: null,
        examples: 0
      });
    }

    // 2) Načti poslední příklady pro daný účet
    const q = await client.query(
      `SELECT role, subject, body, created_at
         FROM style_examples
        WHERE dashboard_user_email = $1 AND connected_email = $2
        ORDER BY created_at DESC
        LIMIT 200`,
      [dashboardUserEmail, email]
    );

    const examples = q.rows || [];
    if (!examples.length) {
      return res.json({
        success: true,
        message: 'Pro tento účet zatím nejsou uloženy žádné příklady.',
        profile: null,
        examples: 0
      });
    }

    // 3) Sestav jednoduchý profil (klidně stejné jako jsme řešili dřív)
    const outgoing = examples.filter(e => e.role === 'outgoing');
    const endings = [];
    const greetings = [];
    for (const e of outgoing) {
      const body = (e.body || '').trim();
      if (!body) continue;
      // naivní detekce pozdravu a závěru
      const lines = body.split('\n').map(s => s.trim()).filter(Boolean);
      if (lines.length) {
        greetings.push(lines[0]);
        endings.push(lines.slice(-1)[0]);
      }
    }

    const profile = {
      default_tone: 'Profesionální',
      default_length: 'Adaptivní',
      common_greetings: [...new Set(greetings)].slice(0, 5),
      common_endings:  [...new Set(endings)].slice(0, 5),
      // sem si můžeš později přidat další statistiky
    };

    return res.json({
      success: true,
      profile,
      examples: examples.length,
      hint: 'Použij tento profil v promptu (SYSTÉMOVÁ INSTRUKCE).',
      debug: debug ? { sample: examples.slice(0,3) } : undefined
    });
  } catch (err) {
    console.error('[STYLE-PROFILE] Error:', err);
    return res.status(500).json({
      success: false,
      message: 'Chyba při čtení profilu',
      detail: debug ? String(err?.message || err) : undefined
    });
  } finally {
    client?.release?.();
  }
});

function sendGmailApiError(res, e, label='Gmail') {
  const msg = String(e?.message || e);
  const status = e?.code || e?.response?.status;

  // čitelný log (response body od Google, pokud je)
  console.error(`[${label}]`, status || '', e?.response?.data || msg);

  if (/Refresh token nenalezen/i.test(msg)) {
    return res.status(404).json({ success:false, message:'Gmail účet není propojen – připoj ho v Nastavení.' });
  }
  if (status === 401 || /invalid_grant/i.test(msg)) {
    return res.status(401).json({ success:false, message:'Přístup k Gmailu vypršel/ byl odvolán – odpoj a znovu připoj.' });
  }
  if (status === 403 && /insufficient.+permissions/i.test(msg)) {
    return res.status(403).json({ success:false, message:'Chybí oprávnění – připoj Gmail se scopem gmail.readonly.' });
  }
  if (status === 403 && /accessNotConfigured/i.test(msg)) {
    return res.status(503).json({ success:false, message:'Gmail API není povoleno v Google Cloudu projektu.' });
  }
  return res.status(500).json({ success:false, message:`Chyba při čtení ${label === 'INBOX' ? 'INBOXu' : 'odeslané pošty'}` });
}


app.post('/api/templates/render', async (req, res) => {
  const { dashboardUserEmail, templateId, content, variables, context } = req.body || {};

  if (!dashboardUserEmail || (!templateId && !content)) {
    return res.status(400).json({ success: false, message: 'Chybí data' });
  }

  let client;
  try {
    client = await pool.connect();

    // 0) Získání textu šablony
    let tplText = String(content ?? '');
    if (!tplText) {
      const r = await client.query(
        'SELECT content FROM templates WHERE id=$1 AND dashboard_user_email=$2',
        [templateId, dashboardUserEmail]
      );
      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: 'Šablona nenalezena' });
      }
      tplText = String(r.rows[0].content || '');
    }

    // 1) Aplikace ručně dodaných proměnných {{var}}
    let filled = tplText;
    if (variables && typeof variables === 'object') {
      for (const [key, val] of Object.entries(variables)) {
        const re = new RegExp(`{{\\s*${escapeRegExp(key)}\\s*}}`, 'g');
        filled = filled.replace(re, String(val ?? ''));
      }
    }

    // === Kontext (co přišlo z FE) ===
    const ctx = context || {};
    const emailBody = String(ctx.emailBody || '');
    const analysis  = ctx.analysis || {};
    const meta      = ctx.meta || {};        // např. { subject, from, date, account }
    const settings  = ctx.settings || {};    // např. { tone, length, signature, ... }

    // === STYLE_PROFILE (systémová instrukce) ===
    let styleProfile = {
      tone: settings.tone || 'Profesionální',
      length: settings.length || 'Střední (1 odstavec)',
      signature: settings.signature || '',
      language: 'cs-CZ'
    };

    // Volitelně: pokus o načtení uloženého profilu z DB (pokud tabulka existuje)
    try {
      const prof = await client.query(
        'SELECT profile_json FROM style_profiles WHERE dashboard_user_email=$1 AND (connected_email=$2 OR $2 IS NULL) LIMIT 1',
        [dashboardUserEmail, meta.account || null]
      );
      if (prof.rowCount && prof.rows[0]?.profile_json) {
        styleProfile = { ...styleProfile, ...prof.rows[0].profile_json };
      }
    } catch (_) {
      // tabulka nemusí existovat — ignoruj
    }

    const systemInstruction =
`SYSTÉMOVÁ INSTRUKCE:
Piš odpovědi podle následujícího stylového profilu (JSON). Pokud není relevantní část v profilu,
použij rozumný default, ale profil má přednost.

STYLE_PROFILE:
${JSON.stringify(styleProfile, null, 2)}
`;

    // 1.5) AI doplnění chybějících {{proměnných}} z emailu
    const missingKeys = Array.from(new Set(
      [...filled.matchAll(/{{\s*([a-zA-Z0-9_]+)\s*}}/g)].map(m => m[1])
    ));

    if (missingKeys.length) {
      const promptVars =
`${systemInstruction}
Jsi asistent pro doplňování proměnných v šabloně emailu.
Máš seznam proměnných, metadata a text původního emailu. Pokud informaci NELZE spolehlivě vyčíst,
dej null nebo prázdný řetězec. NEVYMÝŠLEJ nesmysly.

Vrať POUZE JSON objekt { "klic": "hodnota", ... } bez dalšího textu.

Proměnné k doplnění:
${JSON.stringify(missingKeys)}

Metadata (např. subject, from):
${JSON.stringify(meta).slice(0, 1000)}

Analýza (pokud je k dispozici):
${JSON.stringify(analysis).slice(0, 1200)}

Text emailu:
${emailBody.slice(0, 4000)}

Speciální pravidla (CZ):
- recipientName: vytvoř vhodné ČESKÉ oslovení ("paní Nováková"/"pane Dvořáku") podle „From:“ nebo podpisu.
- senderName: celé jméno OSOBY, která psala původní email (z „From:“ nebo podpisu). Když nejde zjistit, nech prázdné.
- company: název firmy z podpisu/From:/domény (bez právní formy, pokud to dává smysl).
- product: stručný název produktu/služby z předmětu/textu.
- price: přesně tak, jak je v emailu (např. "8 990 Kč", "€120").
- deliveryTime: např. "3–5 pracovních dní" (jen pokud to v emailu je).
- orderNumber: hledej tvary "#2025-0915", "objednávka 12345", "Order 12345".
- issue: jednou větou pojmenuj problém.
- solutionOptionA / solutionOptionB: dvě realistické varianty řešení adekvátní k "issue".
- painPoint: hlavní bolest/priorita firmy v jedné krátké frázi.
- kpi: sledovaný ukazatel ("konverzní poměr", "CAC", "odpovědní doba").
- kpiValue: číselně s jednotkou (např. "32 %", "1,5 s"), jen pokud to v emailu je.
- timeframe: např. "30 dní", "6 týdnů", pokud to lze rozumně odvodit; jinak prázdné.
- step1, step2, step3: tři KONKRÉTNÍ krátké akční kroky (imperativně).
- slot1, slot2: dva KONKRÉTNÍ 15min termíny v blízké budoucnosti (např. "středa 14:00", "čtvrtek 10:00"), česky.
- meetingDate: pokud je v emailu explicitní termín schůzky, vrať jej; jinak prázdné (nedopočítávej).
- ourNextStep / theirNextStep: co uděláme my / co mají udělat oni (jedna krátká věta).
- ourDeadline / theirDeadline / deadline: pokud je v emailu datum/termín, formát "7. 9. 2025" nebo "7. 9. 2025 14:00".
- Hodnoty piš stručně, bez uvozovek navíc a bez vysvětlování.`;

      let inferred = {};
      try {
        const ai = await model.generateContent(promptVars);
        const raw = ai?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
        inferred = JSON.parse(stripJsonFence(raw) || '{}');
      } catch (err) {
        console.warn('AI variable fill failed, skipping.', err?.message);
      }

      // Doplň meetingDate ze slot1 pokud není a slot1 existuje
      if (!inferred?.meetingDate && inferred?.slot1) {
        inferred.meetingDate = inferred.slot1;
      }

      // Fallbacky (pokud ani AI nic nedala)
      const DEFAULTS = {
        solutionOptionA: 'výměna za nový kus',
        solutionOptionB: 'refundace po vrácení zboží',
        kpi: 'konverzní poměr',
        timeframe: '',
        ourNextStep: '',
        ourDeadline: '',
        theirNextStep: '',
        theirDeadline: '',
        meetingDate: '',
        deadline: ''
      };

      // (Pozn.: už NEpoužíváme fallback na settings.signature pro senderName — je to jméno protistrany.)
      // Heuristika: když AI nedoplní senderName, zkus to vyčíst z From:
      if (!inferred?.senderName && meta?.from) {
        const parsed = parseNameFromFromHeader(String(meta.from));
        if (parsed) inferred.senderName = parsed;
      }
      // (volitelné) pokus o extrakci jména z podpisu v textu e-mailu
      if (!inferred?.senderName) {
        const sign = parseNameFromEmailSignature(emailBody);
        if (sign) inferred.senderName = sign;
      }

      for (const key of missingKeys) {
        let val = (inferred?.[key] ?? '').toString().trim();
        if (!val && Object.prototype.hasOwnProperty.call(DEFAULTS, key)) {
          val = DEFAULTS[key];
        }
        if (val) {
          const re = new RegExp(`{{\\s*${escapeRegExp(key)}\\s*}}`, 'g');
          filled = filled.replace(re, val);
        }
      }
    }

    // 2) AI sloty [[AI: ...]]
    const aiSlotRegex = /\[\[\s*AI\s*:(.*?)\]\]/gs;
    const slots = [...filled.matchAll(aiSlotRegex)];
    if (slots.length) {
      for (const m of slots) {
        const whole = m[0];
        const instr = (m[1] || '').trim();

        const prompt =
`${systemInstruction}
Úkol: ${instr}
---
Kontext emailu (text):
${emailBody.slice(0, 4000)}

Analýza (JSON):
${JSON.stringify(analysis).slice(0, 2000)}

Preferovaný tón: ${styleProfile.tone}
Délka: ${styleProfile.length}
Podpis (pokud je vhodné, přidej až úplně na konec odpovědi): ${styleProfile.signature || ''}

Odpověz pouze textem, bez vysvětlivek a bez markdownu.`;

        let aiText = '';
        try {
          const out = await model.generateContent(prompt);
          aiText = (out?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '').trim();
        } catch (err) {
          console.warn('AI slot generation failed, leaving empty.', err?.message);
        }

        filled = filled.replace(whole, aiText);
      }
    }

    return res.json({ success: true, rendered: filled });
  } catch (e) {
    console.error('TEMPLATE RENDER ERROR', e);
    return res.status(500).json({ success: false, message: 'Render selhal' });
  } finally {
    client?.release?.();
  }
});

/* ===== Pomocné funkce ===== */

function stripJsonFence(s = '') {
  return String(s).replace(/^\s*```json\s*/i, '').replace(/\s*```\s*$/i, '').trim();
}

function escapeRegExp(s = '') {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// "John Doe" <john@firma.cz>  |  John Doe <john@firma.cz>  |  john@firma.cz (John Doe)
function parseNameFromFromHeader(from = '') {
  const f = String(from).trim();

  // 1) Úsek v uvozovkách "..."
  const quoted = f.match(/"([^"]+)"/);
  if (quoted?.[1]) return quoted[1].trim();

  // 2) Text před <email>
  const beforeAngle = f.match(/^([^<]+)</);
  if (beforeAngle?.[1]) return beforeAngle[1].trim().replace(/^'+|'+$/g, '');

  // 3) Text v závorkách (email) (Jméno)
  const paren = f.match(/\(([^)]+)\)\s*$/);
  if (paren?.[1]) return paren[1].trim();

  // 4) Když je jen e-mail, zkusit z uživatelské části něco jako "john.doe" => "John Doe"
  const justMail = f.match(/<?([A-Z0-9._%+-]+)@[A-Z0-9.-]+\.[A-Z]{2,}>?/i);
  if (justMail?.[1]) {
    const candidate = justMail[1]
      .replace(/[._-]+/g, ' ')
      .split(' ')
      .map(w => w ? (w[0].toUpperCase() + w.slice(1)) : '')
      .join(' ')
      .trim();
    return candidate || '';
  }

  return '';
}

// jednoduchý heuristický výtah jména z podpisu na konci e-mailu
function parseNameFromEmailSignature(body = '') {
  const text = String(body || '').replace(/\r/g, '');
  // vezmi posledních ~12 řádků
  const lines = text.split('\n').slice(-12).map(l => l.trim()).filter(Boolean);

  // najdi řádek po sign-off “S pozdravem”, “Děkuji”, “Děkujeme”, “Hezký den” apod.
  const signIdx = lines.findIndex(l => /^(s pozdravem|děkuji|děkujeme|hezký den|s úctou)/i.test(l));
  if (signIdx >= 0 && signIdx + 1 < lines.length) {
    const candidate = lines[signIdx + 1];
    if (isLikelyPersonName(candidate)) return candidate;
  }

  // jinak vezmi první řádek, který vypadá jako jméno
  for (const l of lines) {
    if (isLikelyPersonName(l)) return l;
  }
  return '';
}

function isLikelyPersonName(s = '') {
  const words = String(s).trim().split(/\s+/);
  if (words.length < 2 || words.length > 4) return false;
  // jednoduchá heuristika: začíná velkým písmenem a není to firma (s.r.o., a.s., sro, as)
  if (/\b(s\.?r\.?o\.?|a\.?s\.?)\b/i.test(s)) return false;
  return words.every(w => /^[A-ZÁČĎÉĚÍĽĹŇÓŘŠŤÚŮÝŽ][a-záčďéěíľĺňóřšťúůýž-]+$/.test(w));
}





app.post('/api/auth/change-password', async (req, res) => {
  const { email, currentPassword, newPassword, newPasswordConfirm } = req.body || {};
  if (!email || !newPassword || !newPasswordConfirm) {
    return res.status(400).json({ success: false, message: 'Chybí povinná pole.' });
  }
  if (newPassword !== newPasswordConfirm) {
    return res.status(400).json({ success: false, message: 'Nová hesla se neshodují.' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ success: false, message: 'Heslo musí mít alespoň 8 znaků.' });
  }

  const client = await pool.connect();
  try {
    const r = await client.query(
      'SELECT password_hash FROM dashboard_users WHERE email=$1',
      [email]
    );
    if (r.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Uživatel nenalezen.' });
    }

    const oldHash = r.rows[0].password_hash;

    // a) Uživatel už heslo má → ověř currentPassword
    if (oldHash) {
      const ok = await bcrypt.compare(currentPassword || '', oldHash);
      if (!ok) return res.status(401).json({ success: false, message: 'Současné heslo není správné.' });

      // nepovolit stejné heslo
      const same = await bcrypt.compare(newPassword, oldHash);
      if (same) return res.status(400).json({ success: false, message: 'Nové heslo se nesmí shodovat se současným.' });
    }
    // b) Uživatel nemá heslo (Google-only) → povolit „první nastavení“ bez současného hesla

    const newHash = await bcrypt.hash(newPassword, 12);
    await client.query('UPDATE dashboard_users SET password_hash=$1, email_verified=true WHERE email=$2', [newHash, email]);

    return res.json({ success: true, message: oldHash ? 'Heslo bylo změněno.' : 'Heslo bylo nastaveno.' });
  } catch (e) {
    console.error('CHANGE PASSWORD ERROR', e);
    return res.status(500).json({ success: false, message: 'Změna hesla selhala.' });
  } finally {
    client.release();
  }
});



app.post('/api/accounts/set-active', async (req, res) => {
  const { dashboardUserEmail, email, active } = req.body;
  if (!dashboardUserEmail || !email || typeof active !== 'boolean') {
    return res.status(400).json({ success: false, message: 'Chybné parametry.' });
  }

  let client;
  try {
    client = await pool.connect();

    // 1) Gmail účty
    let r = await client.query(
      `UPDATE connected_accounts
       SET active = $1
       WHERE email = $2 AND dashboard_user_email = $3`,
      [active, email, dashboardUserEmail]
    );

    // 2) Pokud se nenašlo, zkus custom účty
    if (r.rowCount === 0) {
      r = await client.query(
        `UPDATE custom_accounts
         SET active = $1
         WHERE email_address = $2 AND dashboard_user_email = $3`,
        [active, email, dashboardUserEmail]
      );
    }

    if (r.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Účet nenalezen.' });
    }

    return res.json({ success: true, message: `Účet ${email} byl ${active ? 'aktivován' : 'deaktivován'}.` });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success: false, message: 'Chyba při ukládání stavu účtu.' });
  } finally {
    if (client) client.release();
  }
});


app.post('/api/auth/register', async (req, res) => {
  const { fullName, email, password } = req.body || {};
  if (!fullName || !email || !password || password.length < 8) {
    return res.status(400).json({ success: false, message: 'Chybné parametry.' });
  }

  const client = await pool.connect();
  try {
    // už existuje social login?
    const exists = await client.query(
      'SELECT email FROM dashboard_users WHERE email = $1',
      [email]
    );
    if (exists.rowCount > 0 && !exists.rows[0].password_hash) {
      // účet existuje jen přes Google – povolíme i heslo
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const verificationToken = crypto.randomBytes(24).toString('hex');

    await client.query(`
      INSERT INTO dashboard_users (email, name, plan, password_hash, email_verified, verification_token)
      VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (email) DO UPDATE
      SET name = EXCLUDED.name,
          password_hash = EXCLUDED.password_hash,
          verification_token = EXCLUDED.verification_token
    `, [email, fullName, 'Starter', passwordHash, /* email_verified: */ true, verificationToken]);

    // TODO: odeslání verifikačního e-mailu (volitelné)
    // Zatím vrátíme úspěch a „přihlásíme“
    return res.json({
      success: true,
      user: { email, name: fullName, plan: 'Starter' }
    });
  } catch (e) {
    console.error('REG ERROR', e);
    return res.status(500).json({ success: false, message: 'Registrace selhala.' });
  } finally {
    client.release();
  }
});




app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Zadejte email i heslo.' });
  }
  const client = await pool.connect();
  try {
    const r = await client.query(
      'SELECT email, name, plan, role, password_hash FROM dashboard_users WHERE email = $1',
      [email]
    );
    if (r.rowCount === 0 || !r.rows[0].password_hash) {
      return res.status(401).json({ success: false, message: 'Nesprávný email nebo heslo.' });
    }
    const ok = await bcrypt.compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ success: false, message: 'Nesprávný email nebo heslo.' });

     return res.json({ success: true, user: { email: r.rows[0].email, name: r.rows[0].name, role: r.rows[0].role, plan: r.rows[0].plan }});
  } catch (e) {
    console.error('LOGIN ERROR', e);
    return res.status(500).json({ success: false, message: 'Přihlášení selhalo.' });
  } finally {
    client.release();
  }
});





// ENDPOINT PRO ZPRACOVÁNÍ SOUHLASU OD GOOGLE (PROPOJENÍ)
app.get('/api/oauth/google/callback', async (req, res) => {
   let client;
    try {
        const code = req.query.code;
        if (!code) throw new Error('Autorizační kód chybí.');

        // přihlášený uživatel (majitel dashboardu) – poslali jsme ho ve state
        const dashboardUserEmail = decodeURIComponent(req.query.state || '');

        const { tokens } = await oauth2Client.getToken(code);
        // email propojené schránky vyčteme z id_token
        const ticket = await loginClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const connectedEmail = payload.email;
        const refreshToken = tokens.refresh_token;

        if (!connectedEmail || !refreshToken) {
            throw new Error('Chybí email nebo refresh token z Google OAuth.');
        }

        client = await pool.connect();

const canAdd = await canAddConnectedAccount(client, dashboardUserEmail || connectedEmail);
if (!canAdd.ok) {
  console.warn(`Limit účtů dosažen: ${canAdd.have}/${canAdd.max} pro ${dashboardUserEmail}`);
  // pošli zpět na FE s chybou
  client.release();
  return res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=limit&reason=accounts`);
}


        // Ujistíme se, že dashboard user existuje (pro jistotu)
        await client.query(
            `INSERT INTO dashboard_users (email, name)
             VALUES ($1, $2)
             ON CONFLICT (email) DO NOTHING`,
            [dashboardUserEmail || connectedEmail, payload.name || null]
        );

        // Uložení/aktualizace propojené schránky k danému uživateli
        await client.query(
            `INSERT INTO connected_accounts (email, refresh_token, dashboard_user_email)
             VALUES ($1, $2, $3)
             ON CONFLICT (email)
             DO UPDATE SET refresh_token = EXCLUDED.refresh_token,
                           dashboard_user_email = EXCLUDED.dashboard_user_email`,
            [connectedEmail, refreshToken, dashboardUserEmail || connectedEmail]
        );

        // volitelně: vytvoř výchozí settings pro kombinaci (user + email), pokud neexistují
        await client.query(
            `INSERT INTO settings (dashboard_user_email, connected_email)
             VALUES ($1, $2)
             ON CONFLICT (dashboard_user_email, connected_email) DO NOTHING`,
            [dashboardUserEmail || connectedEmail, connectedEmail]
        );

        // zpět do FE
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=success&new-email=${encodeURIComponent(connectedEmail)}`);
    } catch (error) {
        console.error("Chyba při zpracování OAuth callbacku:", error.message);
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=error`);
    } finally {
        if (client) client.release();
    }
});


app.get('/api/user/plan', async (req, res) => {
    const { email } = req.query;
    if (!email) return res.status(400).json({ success: false, message: "Chybí email." });
    const client = await pool.connect();
    try {
        const result = await client.query(
            'SELECT plan FROM dashboard_users WHERE email = $1',
            [email]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: "Uživatel nenalezen." });
        }
        res.json({ success: true, plan: result.rows[0].plan });
    } catch (err) {
        console.error("Chyba při načítání tarifu:", err);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst tarif." });
    } finally {
        client.release();
    }
});


app.post('/api/user/plan', async (req, res) => {
    const { email, plan } = req.body;
  if (!email || !plan) return res.status(400).json({ success: false, message: "Chybí email nebo plán." });
  const client = await pool.connect();
  try {
    const p = await client.query(`SELECT max_accounts FROM plans WHERE code = $1`, [plan]);
    if (p.rowCount === 0) return res.status(400).json({ success: false, message: "Neznámý plán." });
    const maxAcc = p.rows[0].max_accounts;

    const c = await client.query(`SELECT COUNT(*)::INT AS c FROM connected_accounts WHERE dashboard_user_email = $1`, [email]);
    if (c.rows[0].c > maxAcc) {
      return res.status(400).json({
        success: false,
        message: `Nelze přejít na ${plan}. Máte připojeno ${c.rows[0].c} účtů, limit je ${maxAcc}.`
      });
    }

    await client.query(`UPDATE dashboard_users SET plan = $1 WHERE email = $2`, [plan, email]);
    res.json({ success: true, message: "Plán byl změněn." });
  } catch (err) {
    console.error("Chyba při ukládání tarifu:", err);
    res.status(500).json({ success: false, message: "Nepodařilo se změnit tarif." });
  } finally {
    client.release();
  }
});




app.get('/api/limits', async (req, res) => {
  const { dashboardUserEmail } = req.query;
  if (!dashboardUserEmail) return res.status(400).json({ success: false, message: "Chybí dashboardUserEmail." });
  const client = await pool.connect();
  try {
    const limits = await getPlanLimits(client, dashboardUserEmail);
    await ensureUsageRow(client, dashboardUserEmail);
    const used = await getUsage(client, dashboardUserEmail);
    res.json({
      success: true,
      plan: limits.code,
      max_accounts: limits.max_accounts,
      monthly_ai_actions: limits.monthly_ai_actions,
      ai_actions_used: used,
      ai_actions_remaining: Math.max(0, limits.monthly_ai_actions - used),
      period_start: currentPeriodStartDateUTC()
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success: false, message: "Nepodařilo se načíst limity." });
  } finally {
    client.release();
  }
});




function currentPeriodStartDateUTC() {
  // první den aktuálního měsíce v UTC jako 'YYYY-MM-DD'
  const now = new Date();
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth(); // 0–11
  return new Date(Date.UTC(y, m, 1)).toISOString().slice(0,10);
}

async function getPlanLimits(client, dashboardUserEmail) {
  // z dashboard_users vezmi plán a z plans načti limity
  const u = await client.query(`SELECT plan FROM dashboard_users WHERE email = $1`, [dashboardUserEmail]);
  if (u.rowCount === 0) throw new Error('Uživatel neexistuje');
  const plan = u.rows[0].plan || 'Starter';
  const p = await client.query(`SELECT code, max_accounts, monthly_ai_actions FROM plans WHERE code = $1`, [plan]);
  if (p.rowCount === 0) throw new Error(`Plán ${plan} není definován v tabulce plans`);
  return p.rows[0];
}

async function ensureUsageRow(client, dashboardUserEmail) {
  const period = currentPeriodStartDateUTC();
  await client.query(`
    INSERT INTO usage_counters (dashboard_user_email, period_start, ai_actions_used)
    VALUES ($1,$2,0)
    ON CONFLICT (dashboard_user_email, period_start) DO NOTHING
  `, [dashboardUserEmail, period]);
}

async function getUsage(client, dashboardUserEmail) {
  const period = currentPeriodStartDateUTC();
  const r = await client.query(`
    SELECT ai_actions_used FROM usage_counters
    WHERE dashboard_user_email = $1 AND period_start = $2
  `, [dashboardUserEmail, period]);
  return r.rowCount ? r.rows[0].ai_actions_used : 0;
}

async function canAddConnectedAccount(client, dashboardUserEmail) {
  const limits = await getPlanLimits(client, dashboardUserEmail);
  const r1 = await client.query(`SELECT COUNT(*)::INT AS c FROM connected_accounts WHERE dashboard_user_email = $1`, [dashboardUserEmail]);
  const r2 = await client.query(`SELECT COUNT(*)::INT AS c FROM custom_accounts WHERE dashboard_user_email = $1`, [dashboardUserEmail]);
  const count = r1.rows[0].c + r2.rows[0].c;
  return { ok: count < limits.max_accounts, max: limits.max_accounts, have: count };
}

async function tryConsumeAiAction(client, dashboardUserEmail) {
  const limits = await getPlanLimits(client, dashboardUserEmail);
  await ensureUsageRow(client, dashboardUserEmail);
  const period = currentPeriodStartDateUTC();
  const r = await client.query(`
    SELECT ai_actions_used FROM usage_counters WHERE dashboard_user_email = $1 AND period_start = $2
  `, [dashboardUserEmail, period]);
  const used = r.rowCount ? r.rows[0].ai_actions_used : 0;
  if (used >= limits.monthly_ai_actions) {
    return { ok: false, used, limit: limits.monthly_ai_actions };
  }
  await client.query(`
    UPDATE usage_counters
    SET ai_actions_used = ai_actions_used + 1
    WHERE dashboard_user_email = $1 AND period_start = $2
  `, [dashboardUserEmail, period]);
  return { ok: true, used: used + 1, limit: limits.monthly_ai_actions };
}





async function listConnectedAccountsHandler(req, res) {
let client;
  try {
    const { dashboardUserEmail } = req.query;
    if (!dashboardUserEmail) {
      return res.status(400).json({ success: false, message: 'Chybí dashboardUserEmail.' });
    }

    client = await pool.connect();

    const r = await client.query(`
      SELECT email AS address, active, created_at, 'gmail'::text AS type
      FROM connected_accounts
      WHERE dashboard_user_email = $1
      UNION ALL
      SELECT email_address AS address, active, created_at, 'custom'::text AS type
      FROM custom_accounts
      WHERE dashboard_user_email = $1
      ORDER BY created_at ASC
    `, [dashboardUserEmail]);

    const accounts = r.rows.map(row => ({
      email: row.address,
      active: !!row.active,
      type: row.type,             // 'gmail' | 'custom' (FE může ignorovat, pokud ho nepotřebuje)
    }));

    // fallback endpoint udrž: /api/accounts/list → vrací jen pole emailů
    if (req.path.endsWith('/list')) {
      return res.json({ success: true, emails: accounts.map(a => a.email) });
    }

    return res.json({ success: true, accounts });
  } catch (err) {
    console.error('Chyba při čtení accounts:', err);
    return res.status(500).json({ success: false, message: 'Nepodařilo se načíst připojené účty.' });
  } finally {
    if (client) client.release();
  }
}

app.get('/api/accounts', listConnectedAccountsHandler);
app.get('/api/accounts/list', listConnectedAccountsHandler); // kvůli fallbacku z FE





app.post('/api/oauth/google/revoke', async (req, res) => {
  let client;
  try {
    const { email, dashboardUserEmail } = req.body;
    if (!email || !dashboardUserEmail) {
      return res.status(400).json({ success: false, message: 'Chybí email nebo dashboardUserEmail.' });
    }

    client = await pool.connect();

    // 1) Zkus Gmail účet
    const rG = await client.query(
      'SELECT refresh_token FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
      [email, dashboardUserEmail]
    );

    if (rG.rowCount > 0) {
      const refreshToken = rG.rows[0].refresh_token;

      // a) Revoke u Googlu (best-effort)
      if (refreshToken) {
        try {
          await oauth2Client.revokeToken(refreshToken);
          console.log(`Token pro ${email} zneplatněn u Googlu.`);
        } catch (e) {
          console.warn('Revoke token failed (pokračuji):', e?.message || e);
        }
      }

      // b) Smazat účet + přidružená data
      await client.query(
        'DELETE FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
        [email, dashboardUserEmail]
      );
      await client.query(
        'DELETE FROM settings WHERE dashboard_user_email=$1 AND connected_email=$2',
        [dashboardUserEmail, email]
      );
      await client.query(
        'DELETE FROM style_profiles WHERE dashboard_user_email=$1 AND connected_email=$2',
        [dashboardUserEmail, email]
      );
      await client.query(
        'DELETE FROM style_examples WHERE dashboard_user_email=$1 AND connected_email=$2',
        [dashboardUserEmail, email]
      );

      return res.status(200).json({ success: true, type: 'gmail', message: 'Účet byl úspěšně odpojen.' });
    }

    // 2) Jinak zkus Custom účet
    const rC = await client.query(
      'SELECT id FROM custom_accounts WHERE dashboard_user_email = $1 AND email_address = $2',
      [dashboardUserEmail, email]
    );

    if (rC.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Účet nenalezen.' });
    }

    await client.query(
      'DELETE FROM custom_accounts WHERE dashboard_user_email = $1 AND email_address = $2',
      [dashboardUserEmail, email]
    );
    await client.query(
      'DELETE FROM settings WHERE dashboard_user_email=$1 AND connected_email=$2',
      [dashboardUserEmail, email]
    );
    await client.query(
      'DELETE FROM style_profiles WHERE dashboard_user_email=$1 AND connected_email=$2',
      [dashboardUserEmail, email]
    );
    await client.query(
      'DELETE FROM style_examples WHERE dashboard_user_email=$1 AND connected_email=$2',
      [dashboardUserEmail, email]
    );

    return res.status(200).json({ success: true, type: 'custom', message: 'Účet byl úspěšně odpojen.' });
  } catch (error) {
    console.error('Chyba při odpojení účtu:', error);
    return res.status(500).json({ success: false, message: 'Nepodařilo se odpojit účet.' });
  } finally {
    if (client) client.release();
  }
});





// === NOVÝ ENDPOINT PRO ODESLÁNÍ ODPOVĚDI ===
app.post('/api/gmail/send-reply', async (req, res) => {
   try {
        const { dashboardUserEmail, email, messageId, replyBody } = req.body;
        if (!dashboardUserEmail || !email || !messageId || !replyBody) {
            return res.status(400).json({ success: false, message: "Chybí povinná data." });
        }

        const db = await pool.connect();


const consume = await tryConsumeAiAction(db, dashboardUserEmail);
    if (!consume.ok) {
      db.release();
      return res.status(429).json({
        success: false,
        message: `Vyčerpán měsíční limit AI akcí (${consume.limit}). Zvažte navýšení tarifu.`
      });
    }



        const r = await db.query(
            'SELECT refresh_token FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
            [email, dashboardUserEmail]
        );
        db.release();

        const refreshToken = r.rows[0]?.refresh_token;
        if (!refreshToken) return res.status(404).json({ success: false, message: "Token nenalezen." });

        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: messageId });
        const originalHeaders = msgResponse.data.payload.headers;
        const find = (n) => originalHeaders.find(h => h.name.toLowerCase() === n)?.value;
        const originalSubject = find('subject') || '';
        const originalFrom = find('from') || '';
        const originalMessageId = find('message-id') || '';
        const originalReferences = find('references') || '';

        const encodeMimeWord = (str) =>
  /[^\x00-\x7F]/.test(str) ? `=?UTF-8?B?${Buffer.from(str, 'utf8').toString('base64')}?=` : str;



const replySubject = originalSubject.startsWith('Re: ') ? originalSubject : `Re: ${originalSubject}`;
// ZMĚNA: žádné jméno, jen adresa
const encodedFrom = `<${email}>`;
const encodedSubject = encodeMimeWord(replySubject);

const lines = [
  `From: ${encodedFrom}`,
  `To: ${originalFrom}`,
  `Subject: ${encodedSubject}`,
  'MIME-Version: 1.0',
  'Content-Type: text/plain; charset=utf-8',
  'Content-Transfer-Encoding: 8bit',
  '',
  replyBody
];

// vlož vláknovací hlavičky jen pokud máme Message-ID původní zprávy
if (originalMessageId) {
  const refs = `${(originalReferences || '').trim()} ${originalMessageId}`.trim();
  // za Subject je vhodné tyto dva řádky vsunout před MIME-Version – ale pořadí v poli nevadí
  lines.splice(3, 0, `In-Reply-To: ${originalMessageId}`, `References: ${refs}`);
}

const raw = Buffer.from(lines.join('\n')).toString('base64url');

await gmail.users.messages.send({
  userId: 'me',
  requestBody: { raw, threadId: msgResponse.data.threadId }
});

res.json({ success: true, message: "Email byl úspěšně odeslán." });
    } catch (error) {
  console.error(
    "Chyba při odesílání emailu:",
    error?.response?.data || error?.message || error
  );
  res.status(500).json({
    success: false,
    message: error?.response?.data?.error?.message || "Nepodařilo se odeslat email."
  });
}
});









app.get('/api/gmail/emails', async (req, res) => {
  let db;
  let imap; // kvůli finally
  try {
    const { email, dashboardUserEmail, status, period, searchQuery } = req.query;
    if (!email || !dashboardUserEmail) {
      return res.status(400).json({ success: false, message: "Chybí email nebo dashboardUserEmail." });
    }

    db = await pool.connect();

    // 1) Zkus Gmail účet
    const acc = await db.query(
      'SELECT refresh_token, active FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
      [email, dashboardUserEmail]
    );

    // 2) Pokud není v Gmail tabulce, zkus custom IMAP
    let isCustom = false;
    let customRow = null;

    if (acc.rowCount === 0) {
      const r = await db.query(`
        SELECT imap_host, imap_port, imap_secure, enc_username, enc_password, active
        FROM custom_accounts
        WHERE dashboard_user_email=$1 AND email_address=$2
        LIMIT 1
      `, [dashboardUserEmail, email]);

      if (r.rowCount === 0) {
        return res.status(404).json({ success: false, message: "Účet nenalezen." });
      }
      isCustom = true;
      customRow = r.rows[0];
    }

    // 3) Kontrola "active"
    if (!isCustom && acc.rows[0].active === false) {
      return res.status(403).json({ success: false, message: "Tento účet je neaktivní." });
    }
    if (isCustom && customRow.active === false) {
      return res.status(403).json({ success: false, message: "Tento účet je neaktivní." });
    }

    // === Gmail větev ===
    if (!isCustom) {
      console.log(`[emails] Gmail account: ${email}`);
      const refreshToken = acc.rows[0].refresh_token;
      if (!refreshToken) {
        return res.status(404).json({ success: false, message: "Pro tento email u tohoto uživatele nebyl nalezen token." });
      }

      db.release(); db = null; // DB už netřeba

      oauth2Client.setCredentials({ refresh_token: refreshToken });
      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

      const queryParts = [];
      if (status === 'unread') queryParts.push('is:unread');
      if (status === 'spam') queryParts.push('in:spam');
      if (period === 'today') queryParts.push('newer_than:1d');
      if (period === 'week') queryParts.push('newer_than:7d');
      if (searchQuery) queryParts.push(String(searchQuery));
      const finalQuery = queryParts.join(' ');

      const listResponse = await gmail.users.messages.list({
        userId: 'me',
        maxResults: 10,
        q: finalQuery
      });

      const messageIds = listResponse.data.messages || [];
      if (messageIds.length === 0) {
        return res.json({ success: true, emails: [], total: 0 });
      }

      const emails = await Promise.all(messageIds.map(async (m) => {
        const mr = await gmail.users.messages.get({
          userId: 'me',
          id: m.id,
          format: 'metadata',
          metadataHeaders: ['Subject', 'From', 'Date']
        });
        const headers = mr.data.payload.headers || [];
        const getHeader = (n) => headers.find(h => h.name === n)?.value || '';
        return {
          id: m.id,
          snippet: mr.data.snippet,
          sender: (getHeader('From').match(/<([^>]+)>/)?.[1] || getHeader('From')).trim().replace(/^mailto:/i, ''),
          subject: getHeader('Subject'),
          date: getHeader('Date')
        };
      }));

      return res.json({ success: true, emails, total: listResponse.data.resultSizeEstimate });
    }

    // === Custom IMAP větev ===
    console.log(`[emails] CUSTOM account: ${email}`);
    try {
      const user = decSecret(customRow.enc_username);
      const pass = decSecret(customRow.enc_password);

      imap = createImapClient({
  host: customRow.imap_host,
  port: customRow.imap_port,
  secure: customRow.imap_secure,
  auth: { user, pass }
});

await imap.connect();
await imap.mailboxOpen('INBOX');

      const out = [];
      let fetched = 0;

      // datumové filtry pro "today" a "week"
      const now = new Date();
      const startOfToday = new Date(now); startOfToday.setHours(0, 0, 0, 0);
      const oneWeekAgo = new Date(now); oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);

      const startSeq = Math.max(1, (imap.mailbox?.exists || 1) - 500);
      for await (let msg of imap.fetch(
        { seq: `${startSeq}:*` },
        { uid: true, envelope: true, internalDate: true, flags: true }
      )) {
        // unread
        if (status === 'unread' && msg.flags?.has('\\Seen')) continue;

        // period
        const d = msg.internalDate;
        if (period === 'today' && (!d || d < startOfToday)) continue;
        if (period === 'week' && (!d || d < oneWeekAgo)) continue;

        const subj = msg.envelope?.subject || '';
        const from = (msg.envelope?.from?.[0]?.address || '').trim();

        // searchQuery (subject + from)
        if (searchQuery) {
          const q = String(searchQuery).toLowerCase();
          if (!subj.toLowerCase().includes(q) && !from.toLowerCase().includes(q)) continue;
        }

        out.push({
          id: String(msg.uid),
          snippet: '',
          sender: from,
          subject: subj,
          date: d ? d.toISOString() : null
        });

        if (++fetched >= 10) break;
      }

      return res.json({ success: true, emails: out, total: out.length });
    } catch (e) {
      console.error("Chyba IMAP:", e);
      return res.status(500).json({ success: false, message: "Nepodařilo se načíst emaily (custom)." });
    } finally {
      try { if (imap?.connected) await imap.logout(); } catch {}
      if (db) { db.release(); db = null; }
    }

  } catch (error) {
    if (imap?.connected) { try { await imap.logout(); } catch {} }
    if (db) { try { db.release(); } catch {} }
    console.error("Chyba při načítání emailů:", error?.message || error);
    return res.status(500).json({ success: false, message: "Nepodařilo se načíst emaily." });
  }
});


app.get('/api/gmail/message-body', async (req, res) => {
  try {
    const { dashboardUserEmail, email, messageId } = req.query || {};
    if (!dashboardUserEmail || !email || !messageId) {
      return res.status(400).json({ success:false, message:'Chybí data (dashboardUserEmail, email, messageId).' });
    }

    const db = await pool.connect();
    const rTok = await db.query(
      'SELECT refresh_token FROM connected_accounts WHERE email=$1 AND dashboard_user_email=$2',
      [email, dashboardUserEmail]
    );
    db.release();

    const refreshToken = rTok.rows[0]?.refresh_token;
    if (!refreshToken) return res.status(404).json({ success:false, message:'Token nenalezen.' });

    oauth2Client.setCredentials({ refresh_token: refreshToken });
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    const msg = await gmail.users.messages.get({ userId:'me', id: messageId });
    // vytáhnout text/plain nebo převést html na text
    const getText = (payload) => {
      const b64 = (d) => Buffer.from(d, 'base64').toString('utf8');
      const strip = (html) => html.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').trim();
      if (payload.mimeType === 'text/plain' && payload.body?.data) return b64(payload.body.data);
      if (payload.parts && Array.isArray(payload.parts)) {
        // preferuj text/plain
        const plain = payload.parts.find(p => p.mimeType === 'text/plain' && p.body?.data);
        if (plain) return b64(plain.body.data);
        const html = payload.parts.find(p => p.mimeType === 'text/html' && p.body?.data);
        if (html) return strip(b64(html.body.data));
        // rekurzivně projít části
        for (const p of payload.parts) {
          const t = getText(p);
          if (t) return t;
        }
      }
      if (payload.mimeType === 'text/html' && payload.body?.data) {
        return strip(b64(payload.body.data));
      }
      if (payload.body?.data) return b64(payload.body.data);
      return '';
    };

    const body = getText(msg.data.payload) || '';
    return res.json({ success:true, body });
  } catch (e) {
    console.error('[gmail/message-body] error:', e);
    return res.status(500).json({ success:false, message:'Načtení těla zprávy selhalo.' });
  }
});





async function handleCustomAnalyzeEmail(req, res) {
  try {
    // podpora POST (body) i GET (query)
    const src = req.method === 'GET' ? (req.query || {}) : (req.body || {});
    const { dashboardUserEmail, emailAddress, uid } = src;

    if (!dashboardUserEmail || !emailAddress || !uid) {
      return res.status(400).json({ success:false, message:'Chybí data (dashboardUserEmail, emailAddress, uid).' });
    }

    // načíst limity
    const db = await pool.connect();
    const consume = await tryConsumeAiAction(db, dashboardUserEmail);
    if (!consume.ok) {
      db.release();
      return res.status(429).json({ success:false, message:`Vyčerpán měsíční limit AI akcí (${consume.limit}).` });
    }

    // načíst účet + settings
    const rAcc = await db.query(`
      SELECT imap_host, imap_port, imap_secure, enc_username, enc_password
      FROM custom_accounts
      WHERE dashboard_user_email=$1 AND email_address=$2 AND active=true
      LIMIT 1
    `, [dashboardUserEmail, emailAddress]);
    const rSet = await db.query(`
      SELECT tone, length, signature FROM settings
      WHERE dashboard_user_email=$1 AND connected_email=$2
      LIMIT 1
    `, [dashboardUserEmail, emailAddress]);
    
    // PŘIDÁNO: Načtení FAQ pro daný účet
    const rFaq = await db.query(`
      SELECT question, answer FROM faqs
      WHERE dashboard_user_email=$1 AND connected_email=$2
    `, [dashboardUserEmail, emailAddress]);

    db.release();

    if (!rAcc.rowCount) {
      return res.status(404).json({ success:false, message:'Custom účet nenalezen.' });
    }
    const st = rSet.rows[0] || { tone:'Profesionální', length:'Adaptivní', signature:'' };

    const user = decSecret(rAcc.rows[0].enc_username);
    const pass = decSecret(rAcc.rows[0].enc_password);

    // === OPRAVA: vytvořit IMAP klienta a připojit se ===
    const imap = createImapClient({
      host: rAcc.rows[0].imap_host,
      port: Number(rAcc.rows[0].imap_port),
      secure: !!rAcc.rows[0].imap_secure,
      auth: { user, pass }
    });

    await imap.connect();
    await imap.mailboxOpen('INBOX');

    // stáhnout zprávu dle UID
    const { content } = await imap.download(Number(uid), null, { uid: true });
    const chunks = [];
    for await (const c of content) chunks.push(c);

    // vždy se odhlásit
    try { if (imap?.connected) await imap.logout(); } catch {}

    const parsed = await simpleParser(Buffer.concat(chunks));
    const emailBody = parsed.text || (parsed.html ? parsed.html.replace(/<[^>]+>/g,'').trim() : '');

    
    const messageId = parsed.messageId || null;
    let references = parsed.references || null;
    if (Array.isArray(references)) {
        references = references.join(' ');
    }

    const styleProfile = {
      tone: st?.tone || 'Formální',
      length: st?.length || 'Střední (1 odstavec)',
      signature: st?.signature || '',
      language: 'cs-CZ'
    };

    const systemInstruction = `SYSTÉMOVÁ INSTRUKCE:
Piš odpovědi podle následujícího stylového profilu (JSON). Pokud není relevantní část v profilu,
použij rozumný default, ale profil má přednost.

STYLE_PROFILE:
${JSON.stringify(styleProfile, null, 2)}

Pravidla pro tvorbu "suggested_reply":
- Dodrž tón (tone) ze STYLE_PROFILE:
  - "Formální" = spisovný, zdvořilý, bez slangových výrazů.
  - "Neformální" = přátelský, uvolněný tón.
- Dodrž délku (length) ze STYLE_PROFILE:
  - "Krátká" = 1–2 věty.
  - "Střední" = 1 odstavec (cca 3–6 vět).
  - "Dlouhá" = více odstavců, podrobnější.
- Pokud STYLE_PROFILE.signature není prázdný:
  - Připoj podpis na konec odpovědi (dvě nové řádky před podpisem).
  - Podpis neduplikuj, pokud už v textu je.
`;
    // PŘIDÁNO: Sestavení kontextu z FAQ
    let faqContext = '';
    if (rFaq.rowCount > 0) {
      faqContext = 'Při generování odpovědi se inspiruj a čerpej informace z následující FAQ databáze:\n---\n';
      faqContext += rFaq.rows.map(row => `Otázka: ${row.question}\nOdpověď: ${row.answer}`).join('\n\n');
      faqContext += '\n---\n\n';
    }
    
    const task = `${faqContext}Jsi profesionální e-mailový asistent. Analyzuj e-mail a vrať POUZE VALIDNÍ JSON ve tvaru:
{
  "summary": "stručné shrnutí",
  "sentiment": "pozitivní|neutrální|negativní",
  "suggested_reply": "plný text odpovědi splňující STYLE_PROFILE a pravidla výše"
}
Bez jakéhokoli dalšího textu mimo JSON. Odpovědi piš česky.

Text e-mailu:
---
${String(emailBody).slice(0, 3000)}
---
`;

    const geminiResult = await model.generateContent(`${systemInstruction}\n${task}`);
    const raw = geminiResult?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    const cleaned = raw.replace(/```json|```/g, '').trim();

    let analysis = {};
    try {
      analysis = JSON.parse(cleaned);
    } catch {
      const fix = await model.generateContent(
        `Oprav na validní JSON { "summary":"", "sentiment":"", "suggested_reply":"" }:\n${raw}`
      );
      analysis = JSON.parse(
        fix.response.candidates[0].content.parts[0].text.replace(/```json|```/g, '').trim()
      );
    }

    const debugOut = {};
    if ((req.query && req.query.debug === '1') || (req.body && req.body.debug === '1')) {
      debugOut.styleProfile = styleProfile;
    }

     return res.json({
        success: true,
        analysis,
        emailBody,
        headers: { messageId, references }, // <-- PŘIDÁNO
        ...debugOut
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ success:false, message:'Analýza selhala.' });
  }
}






// POST (původní cesta)
app.post('/api/custom-email/analyze-email', handleCustomAnalyzeEmail);

// GET alias (když FE posílá query parametry)
app.get('/api/custom-email/analyze-email', handleCustomAnalyzeEmail);

// Volitelně kompatibilní aliasy, kdyby FE trefoval jinou URL:
app.post('/api/custom-email/analyze', handleCustomAnalyzeEmail);
app.get('/api/custom-email/analyze', handleCustomAnalyzeEmail);

app.get('/api/custom-email/message-body', async (req, res) => {
  try {
    const { dashboardUserEmail, emailAddress, uid } = req.query || {};
    if (!dashboardUserEmail || !emailAddress || !uid) {
      return res.status(400).json({ success:false, message:'Chybí data (dashboardUserEmail, emailAddress, uid).' });
    }

    const db = await pool.connect();
    const rAcc = await db.query(`
      SELECT imap_host, imap_port, imap_secure, enc_username, enc_password, active
      FROM custom_accounts
      WHERE dashboard_user_email=$1 AND email_address=$2
      LIMIT 1
    `, [dashboardUserEmail, emailAddress]);
    db.release();

    if (!rAcc.rowCount) return res.status(404).json({ success:false, message:'Custom účet nenalezen.' });
    if (rAcc.rows[0].active === false) return res.status(403).json({ success:false, message:'Tento účet je neaktivní.' });

    const user = decSecret(rAcc.rows[0].enc_username);
    const pass = decSecret(rAcc.rows[0].enc_password);
    const imap = createImapClient({
      host: rAcc.rows[0].imap_host,
      port: Number(rAcc.rows[0].imap_port),
      secure: !!rAcc.rows[0].imap_secure,
      auth: { user, pass }
    });

    await imap.connect();
    await imap.mailboxOpen('INBOX');

    const { content } = await imap.download(Number(uid), null, { uid: true });
    const chunks = [];
    for await (const c of content) chunks.push(c);
    await imap.logout().catch(()=>{});

    const parsed = await simpleParser(Buffer.concat(chunks));
    // preferuj text; když chybí, stripni html
    const bodyText = parsed.text || (parsed.html ? parsed.html.replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g,'').trim() : '') || '';
    return res.json({ success:true, body: bodyText });
  } catch (e) {
    console.error('[custom-email/message-body] error:', e);
    return res.status(500).json({ success:false, message:'Načtení těla zprávy selhalo.' });
  }
});






app.post('/api/custom-email/send-reply', async (req, res) => {
 const { dashboardUserEmail, emailAddress, to, subject, text, fromName, origMessageId, origReferences, replyToUid } = req.body || {};

  if (!dashboardUserEmail || !emailAddress || !to || !subject || !text || !origMessageId || !replyToUid) {
    return res.status(400).json({ success: false, message: 'Chybí povinná data pro odeslání.' });
  }

  const db = await pool.connect();
  let accountDetails;
  try {
    const rAcc = await db.query(`
      SELECT smtp_host, smtp_port, smtp_secure, enc_username, enc_password, active,
             imap_host, imap_port, imap_secure
      FROM custom_accounts
      WHERE dashboard_user_email=$1 AND email_address=$2 AND active=true
      LIMIT 1
    `, [dashboardUserEmail, emailAddress]);
    if (!rAcc.rowCount) return res.status(404).json({ success: false, message: 'Custom účet nenalezen.' });
    accountDetails = rAcc.rows[0];
  } finally {
    db.release();
  }

  const user = decSecret(accountDetails.enc_username);
  const pass = decSecret(accountDetails.enc_password);

  try {
    // Krok 1 a 2: Sestavení a odeslání odpovědi (beze změny)
    const toAddr = extractEmail(to);
    const toName = parseNameFromFromHeader(String(to)) || '';
    const replySubject = subject?.trim() ? (subject.startsWith('Re: ') ? subject : `Re: ${subject}`) : 'Re: (bez předmětu)';
    const fromHeader = fromName ? `${libmime.encodeWord(fromName, 'B', 'utf-8')} <${emailAddress}>` : emailAddress;
    const toHeader = toName ? `${libmime.encodeWord(toName, 'B', 'utf-8')} <${toAddr}>` : toAddr;
    const rawLines = [
      `From: ${fromHeader}`, `To: ${toHeader}`, `Subject: ${libmime.encodeWord(replySubject, 'B', 'utf-8')}`,
      `In-Reply-To: ${origMessageId}`, `References: ${(origReferences ? `${origReferences} ${origMessageId}` : origMessageId).trim()}`,
      'MIME-Version: 1.0', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: 8bit', '', text
    ];
    const rawMessage = rawLines.join('\r\n');
    const transporter = nodemailer.createTransport({
      host: accountDetails.smtp_host, port: Number(accountDetails.smtp_port), secure: !!accountDetails.smtp_secure,
      auth: { user, pass }, tls: { rejectUnauthorized: false }
    });
    await transporter.sendMail({ from: fromHeader, to: toHeader, raw: rawMessage });
    console.log(`[OK] Odpověď pro ${toAddr} byla odeslána.`);

    // Připojení k IMAP pro další operace
    const imapClient = createImapClient({
        host: accountDetails.imap_host, port: accountDetails.imap_port,
        secure: accountDetails.imap_secure, auth: { user, pass }
    });

    try {
        await imapClient.connect();

        // === NOVÝ KROK: Označení původní zprávy jako přečtené a zodpovězené ===
        try {
            await imapClient.mailboxOpen('INBOX'); // Otevřeme Doručenou poštu
            await imapClient.messageFlagsAdd({ uid: String(replyToUid) }, ['\\Seen', '\\Answered']);
            console.log(`[OK] Původní zpráva (UID: ${replyToUid}) byla označena jako přečtená a zodpovězená.`);
        } catch (flagError) {
            console.warn(`[VAROVÁNÍ] Nepodařilo se označit původní zprávu:`, flagError.message);
        }
        // ======================================================================

        // Krok 3: Uložení kopie do odeslané pošty (beze změny)
        const mailboxes = await imapClient.list();
        let sentFolder = mailboxes.find(m => m && m.specialUse && m.specialUse === '\\Sent');
        if (!sentFolder) {
            sentFolder = mailboxes.find(m => (m && m.path) && m.path.toLowerCase() === 'inbox.sent items');
        }
        if (sentFolder) {
            // mailboxOpen se automaticky přepne na správnou složku
            await imapClient.append(sentFolder.path, rawMessage, ['\\Seen']);
            console.log(`[OK] Kopie odpovědi uložena do složky "${sentFolder.path}".`);
        } else {
            console.warn(`[VAROVÁNÍ] Nepodařilo se najít složku pro odeslanou poštu. Kopie nebyla uložena.`);
        }

    } catch (imapError) {
        console.error('[CHYBA] Během IMAP operací došlo k chybě:', imapError);
    } finally {
        if (imapClient.connected) await imapClient.logout();
    }

    return res.json({ success: true, message: 'Odpověď byla úspěšně odeslána a uložena.' });

  } catch (e) {
    console.error('[custom-email/send-reply] Kritická chyba při odesílání:', e);
    return res.status(500).json({ success: false, message: e?.message || 'Odeslání selhalo.' });
  }
});







// === UNIFIED ENDPOINT: zvládne Gmail i Custom na stejné URL ===
app.post('/api/gmail/analyze-email', async (req, res) => {
  // Pokud FE poslal parametry custom účtu, rovnou použij náš custom handler
  const { dashboardUserEmail, emailAddress, uid, messageId } = req.body || {};
  if (!messageId && emailAddress && uid) {
    // FE poslal custom data omylem na /api/gmail/analyze-email -> obsloužíme
    return handleCustomAnalyzeEmail(req, res);
  }

  try {
     const { email } = req.body;
    if (!dashboardUserEmail || !email || !messageId) {
      return res.status(400).json({ success: false, message: "Chybí data." });
    }

    const db = await pool.connect();

    const consume = await tryConsumeAiAction(db, dashboardUserEmail);
    if (!consume.ok) {
      db.release();
      return res.status(429).json({
        success: false,
        message: `Vyčerpán měsíční limit AI akcí (${consume.limit}). Zvažte navýšení tarifu.`
      });
    }

    const rTok = await db.query(
      'SELECT refresh_token FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
      [email, dashboardUserEmail]
    );
    
    const rSet = await db.query(
      'SELECT * FROM settings WHERE dashboard_user_email = $1 AND connected_email = $2',
      [dashboardUserEmail, email]
    );

    //Načtení FAQ i pro Gmail účet
    const rFaq = await db.query(
      'SELECT question, answer FROM faqs WHERE dashboard_user_email = $1 AND connected_email = $2',
      [dashboardUserEmail, email]
    );

    db.release();

    const refreshToken = rTok.rows[0]?.refresh_token;
    const settings = rSet.rows[0];
    if (!refreshToken || !settings) {
      return res.status(404).json({ success: false, message: "Token nebo nastavení nenalezeno." });
    }

    oauth2Client.setCredentials({ refresh_token: refreshToken });
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const msgResponse = await gmail.users.messages.get({ userId: 'me', id: messageId });

    let emailBody = '';
    if (msgResponse.data.payload.parts) {
      const part = msgResponse.data.payload.parts.find(p => p.mimeType === 'text/plain');
      if (part?.body?.data) emailBody = Buffer.from(part.body.data, 'base64').toString('utf-8');
    } else if (msgResponse.data.payload.body?.data) {
      emailBody = Buffer.from(msgResponse.data.payload.body.data, 'base64').toString('utf-8');
    }

const styleProfile = {
  tone: settings?.tone || 'Formální',
  length: settings?.length || 'Střední (1 odstavec)',
  signature: settings?.signature || '',
  language: 'cs-CZ'
};



    
const systemInstruction = `SYSTÉMOVÁ INSTRUKCE:
Piš odpovědi podle následujícího stylového profilu (JSON). Pokud není relevantní část v profilu,
použij rozumný default, ale profil má přednost.

STYLE_PROFILE:
${JSON.stringify(styleProfile, null, 2)}

Pravidla pro tvorbu "suggested_reply":
- Dodrž tón (tone) ze STYLE_PROFILE:
  - "Formální" = spisovný, zdvořilý, bez slangových výrazů.
  - "Neformální" = přátelský, uvolněný tón.
- Dodrž délku (length) ze STYLE_PROFILE:
  - "Krátká" = 1–2 věty.
  - "Střední" = 1 odstavec (cca 3–6 vět).
  - "Dlouhá" = více odstavců, podrobnější.
- Pokud STYLE_PROFILE.signature není prázdný:
  - Připoj podpis na konec odpovědi (dvě nové řádky před podpisem).
  - Podpis neduplikuj, pokud už v textu je.
`;

    //  Sestavení kontextu z FAQ pro Gmail
    let faqContext = '';
    if (rFaq.rowCount > 0) {
      faqContext = 'Při generování odpovědi se inspiruj a čerpej informace z následující FAQ databáze:\n---\n';
      faqContext += rFaq.rows.map(row => `Otázka: ${row.question}\nOdpověď: ${row.answer}`).join('\n\n');
      faqContext += '\n---\n\n';
    }

    const task = `${faqContext}Jsi profesionální e-mailový asistent. Analyzuj e-mail a vrať POUZE VALIDNÍ JSON ve tvaru:
{
  "summary": "stručné shrnutí",
  "sentiment": "pozitivní|neutrální|negativní",
  "suggested_reply": "plný text odpovědi splňující STYLE_PROFILE a pravidla výše"
}
Bez jakéhokoli dalšího textu mimo JSON. Odpovědi piš česky.

Text e-mailu:
---
${String(emailBody).slice(0, 3000)}
---`;

    const prompt = `${systemInstruction}\n${task}`;
    const geminiResult = await model.generateContent(prompt);

    const raw = geminiResult?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '';
    const cleaned = raw.replace(/```json|```/g, '').trim();

    let analysis;
    try {
      analysis = JSON.parse(cleaned);
    } catch {
      const fix = await model.generateContent(
        `Oprav tento text na validní JSON se strukturou { "summary": "", "sentiment": "", "suggested_reply": "" }:\n${raw}`
      );
      analysis = JSON.parse(
        fix.response.candidates[0].content.parts[0].text.replace(/```json|```/g, '').trim()
      );
    }

    const debugOut = {};
    if (req.query?.debug === '1') {
      debugOut.styleProfile = styleProfile;
    }

    return res.json({ success: true, analysis, emailBody, ...debugOut });

  } catch (error) {
    console.error("Chyba při analýze emailu:", error);
    return res.status(500).json({ success: false, message: "Nepodařilo se analyzovat email." });
  }
});






// Endpoint pro načtení nastavení
app.get('/api/settings', async (req, res) => {
    let client;
    try {
        const { dashboardUserEmail, email } = req.query; // email = connected_email
        if (!dashboardUserEmail || !email) {
            return res.status(400).json({ success: false, message: "Chybí dashboardUserEmail nebo email." });
        }
        client = await pool.connect();
        let result = await client.query(
            'SELECT * FROM settings WHERE dashboard_user_email = $1 AND connected_email = $2',
            [dashboardUserEmail, email]
        );
        if (result.rows.length === 0) {
            await client.query(
                'INSERT INTO settings (dashboard_user_email, connected_email) VALUES ($1, $2)',
                [dashboardUserEmail, email]
            );
            result = await client.query(
                'SELECT * FROM settings WHERE dashboard_user_email = $1 AND connected_email = $2',
                [dashboardUserEmail, email]
            );
        }
        res.json({ success: true, settings: result.rows[0] });
    } catch (error) {
        console.error("Chyba při načítání nastavení:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst nastavení." });
    } finally {
        if (client) client.release();
    }
});



app.get('/api/templates', async (req, res) => {
  const email = req.query.dashboardUserEmail;
  const category = req.query.category;
  if (!email) return res.status(400).json({ success:false, message:'Chybí dashboardUserEmail' });
  const client = await pool.connect();
  try {
    const args = [email];
    let sql = `
      SELECT id, name, category, content, uses, success_rate, created_at, updated_at
      FROM templates
      WHERE dashboard_user_email=$1
    `;
    if (category && category !== 'Vše') {
      sql += ' AND category = $2';
      args.push(category);
    }
    sql += ' ORDER BY updated_at DESC';

    const r = await client.query(sql, args);
    res.json({ success:true, templates:r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Nepodařilo se načíst šablony' });
  } finally { client.release(); }
});

// Create
app.post('/api/templates', async (req, res) => {
  const { dashboardUserEmail, name, category, content } = req.body || {};
  if (!dashboardUserEmail || !name || !content) {
    return res.status(400).json({ success:false, message:'Chybí data' });
  }
  const client = await pool.connect();
  try {
    const r = await client.query(
      `INSERT INTO templates (dashboard_user_email, name, category, content)
       VALUES ($1,$2,$3,$4)
       RETURNING id, name, category, content, uses, success_rate, created_at, updated_at`,
      [dashboardUserEmail, name, category || 'Obecné', content]
    );
    res.json({ success:true, template:r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Nepodařilo se vytvořit šablonu' });
  } finally { client.release(); }
});


app.get('/api/faq', async (req, res) => {
  const { dashboardUserEmail, email } = req.query || {};
  if (!dashboardUserEmail || !email) return res.status(400).json({ success:false, message:'Chybí parametry.' });

  const db = await pool.connect();
  try {
    const r = await db.query(
      `SELECT id, question, answer, source, updated_at
         FROM faqs
        WHERE dashboard_user_email=$1 AND connected_email=$2
        ORDER BY updated_at DESC, id DESC`,
      [dashboardUserEmail, email]
    );
    res.json({ success:true, faqs:r.rows });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Načtení FAQ selhalo.' });
  } finally { db.release(); }
});



app.post('/api/faq', async (req, res) => {
  const { dashboardUserEmail, email, question, answer } = req.body || {};
  if (!dashboardUserEmail || !email || !question || !answer) {
    return res.status(400).json({ success:false, message:'Chybí data.' });
  }
  const db = await pool.connect();
  try {
    const r = await db.query(
      `INSERT INTO faqs (dashboard_user_email, connected_email, question, answer)
       VALUES ($1,$2,$3,$4)
       RETURNING id, question, answer, source, updated_at`,
      [dashboardUserEmail, email, question, answer]
    );
    res.json({ success:true, faq:r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Uložení FAQ selhalo.' });
  } finally { db.release(); }
});



app.put('/api/faq/:id', async (req, res) => {
  const id = Number(req.params.id);
  const { dashboardUserEmail, email, question, answer } = req.body || {};
  if (!id || !dashboardUserEmail || !email || !question || !answer) {
    return res.status(400).json({ success:false, message:'Chybí data.' });
  }
  const db = await pool.connect();
  try {
    const r = await db.query(
      `UPDATE faqs
          SET question=$1, answer=$2, updated_at=NOW()
        WHERE id=$3 AND dashboard_user_email=$4 AND connected_email=$5
        RETURNING id, question, answer, source, updated_at`,
      [question, answer, id, dashboardUserEmail, email]
    );
    if (!r.rowCount) return res.status(404).json({ success:false, message:'FAQ položka nenalezena.' });
    res.json({ success:true, faq:r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Úprava FAQ selhala.' });
  } finally { db.release(); }
});



app.delete('/api/faq/:id', async (req, res) => {
  const id = Number(req.params.id);
  const { dashboardUserEmail, email } = req.query || {};
  if (!id || !dashboardUserEmail || !email) {
    return res.status(400).json({ success:false, message:'Chybí data.' });
  }
  const db = await pool.connect();
  try {
    const r = await db.query(
      `DELETE FROM faqs
        WHERE id=$1 AND dashboard_user_email=$2 AND connected_email=$3`,
      [id, dashboardUserEmail, email]
    );
    if (!r.rowCount) return res.status(404).json({ success:false, message:'FAQ položka nenalezena.' });
    res.json({ success:true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Smazání FAQ selhalo.' });
  } finally { db.release(); }
});



app.post('/api/faq/regenerate', async (req, res) => {
  try {
    const { dashboardUserEmail, email, limit = 120 } = req.body || {};
    if (!dashboardUserEmail || !email) {
      return res.status(400).json({ success:false, message:'Chybí parametry.' });
    }

    const db = await pool.connect();
    const consume = await tryConsumeAiAction(db, dashboardUserEmail);
    if (!consume.ok) {
      db.release();
      return res.status(429).json({ success:false, message:`Vyčerpán měsíční limit AI akcí (${consume.limit}).` });
    }

    // Vytáhni poslední N příkladů pro tento účet
    const ex = await db.query(
      `SELECT role, subject, body
         FROM style_examples
        WHERE dashboard_user_email=$1 AND connected_email=$2
        ORDER BY created_at DESC
        LIMIT $3`,
      [dashboardUserEmail, email, Math.min(Number(limit)||120, 300)]
    );
    const examples = ex.rows || [];
    db.release();

    if (!examples.length) {
      return res.json({ success:true, created:0, faqs:[] });
    }

    // Prompt: ze vzorků udělej 8–15 FAQ (Q/A) jako JSON
    const prompt = `
Jsi e-mailový asistent. Z následujících vzorků e-mailové komunikace vytvoř seznam FAQ pro daný účet.
FAQ má zachytit NEJČASTĚJŠÍ dotazy a typické odpovědi firmy. Vrať POUZE validní JSON pole:
[
  {"question":"…","answer":"…"},
  ...
]
Počet 8–15, bez duplicit, česky, krátké a praktické.
Vzorky (JSON řádky):
${examples.map(e => JSON.stringify(e)).join('\n').slice(0, 15000)}
    `.trim();

    const out = await model.generateContent(prompt);
    const raw = out?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '[]';
    let faqs = [];
    try { faqs = JSON.parse(raw.replace(/```json|```/g,'').trim()); }
    catch {
      // oprav JSON
      const fix = await model.generateContent(`Oprav na validní JSON pole Q/A:\n${raw}`);
      faqs = JSON.parse(fix.response.candidates[0].content.parts[0].text.replace(/```json|```/g,'').trim());
    }

    // Ulož: smaž staré a vlož nové (pro daný účet)
    const db2 = await pool.connect();
    try {
      await db2.query(`DELETE FROM faqs WHERE dashboard_user_email=$1 AND connected_email=$2`, [dashboardUserEmail, email]);
      for (const qa of faqs) {
        if (!qa?.question || !qa?.answer) continue;
        await db2.query(
          `INSERT INTO faqs (dashboard_user_email, connected_email, question, answer)
           VALUES ($1,$2,$3,$4)`,
          [dashboardUserEmail, email, qa.question.trim(), qa.answer.trim()]
        );
      }
    } finally { db2.release(); }

    res.json({ success:true, created: faqs.length, faqs });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Regenerace FAQ selhala.' });
  }
});



// Update
app.put('/api/templates/:id', async (req, res) => {
  const id = Number(req.params.id);
  const { dashboardUserEmail, name, category, content } = req.body || {};
  if (!dashboardUserEmail || !id || !name || !content) {
    return res.status(400).json({ success:false, message:'Chybí data' });
  }
  const client = await pool.connect();
  try {
    const r = await client.query(
      `UPDATE templates
       SET name=$1, category=$2, content=$3, updated_at=NOW()
       WHERE id=$4 AND dashboard_user_email=$5
       RETURNING id, name, category, content, uses, success_rate, created_at, updated_at`,
      [name, category || 'Obecné', content, id, dashboardUserEmail]
    );
    if (r.rowCount === 0) return res.status(404).json({ success:false, message:'Šablona nenalezena' });
    res.json({ success:true, template:r.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Nepodařilo se upravit šablonu' });
  } finally { client.release(); }
});

// Delete
app.delete('/api/templates/:id', async (req, res) => {
  const id = Number(req.params.id);
  const email = req.query.dashboardUserEmail;
  if (!email || !id) return res.status(400).json({ success:false, message:'Chybí data' });
  const client = await pool.connect();
  try {
    const r = await client.query(
      `DELETE FROM templates WHERE id=$1 AND dashboard_user_email=$2`,
      [id, email]
    );
    if (r.rowCount === 0) return res.status(404).json({ success:false, message:'Šablona nenalezena' });
    res.json({ success:true, message:'Šablona smazána' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ success:false, message:'Nepodařilo se smazat šablonu' });
  } finally { client.release(); }
});

// (Volitelné) inkrementace použití po odeslání mailu s template_id
app.post('/api/templates/:id/increment-use', async (req,res) => {
  const id = Number(req.params.id);
  const email = req.body?.dashboardUserEmail;
  if (!email || !id) return res.status(400).json({ success:false, message:'Chybí data' });
  const client = await pool.connect();
  try {
    await client.query(
      `UPDATE templates SET uses = uses + 1, updated_at=NOW()
       WHERE id=$1 AND dashboard_user_email=$2`,
      [id, email]
    );
    res.json({ success:true });
  } catch(e){
    console.error(e);
    res.status(500).json({ success:false });
  } finally { client.release(); }
});





// Endpoint pro uložení nastavení
app.post('/api/settings', async (req, res) => {
    let client;
    try {
        const { dashboardUserEmail, email, tone, length, signature, auto_reply, approval_required, spam_filter } = req.body;
        if (!dashboardUserEmail || !email) {
            return res.status(400).json({ success: false, message: "Chybí dashboardUserEmail nebo email." });
        }
        client = await pool.connect();
        await client.query(
            `INSERT INTO settings (dashboard_user_email, connected_email, tone, length, signature, auto_reply, approval_required, spam_filter)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             ON CONFLICT (dashboard_user_email, connected_email)
             DO UPDATE SET tone = EXCLUDED.tone,
                           length = EXCLUDED.length,
                           signature = EXCLUDED.signature,
                           auto_reply = EXCLUDED.auto_reply,
                           approval_required = EXCLUDED.approval_required,
                           spam_filter = EXCLUDED.spam_filter`,
            [dashboardUserEmail, email, tone, length, signature, auto_reply, approval_required, spam_filter]
        );
        res.json({ success: true, message: "Nastavení bylo úspěšně uloženo." });
    } catch (error) {
        console.error("Chyba při ukládání nastavení:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se uložit nastavení." });
    } finally {
        if (client) client.release();
    }
});


// 
// ===================================================================
// === AUTOMATICKÝ EMAIL WORKER (SPAM + SCHVALOVÁNÍ) ================
// ===================================================================

async function runEmailWorker() {
  console.log('🤖 Spouštím automatickou kontrolu emailů...');
  let dbClient;
  try {
    dbClient = await pool.connect();
    // Vezmeme všechny aktivní propojené schránky s jejich nastavením
    const { rows: accounts } = await dbClient.query(`
      SELECT
        ca.email AS connected_email,
        ca.refresh_token,
        ca.dashboard_user_email,
        ca.active,
        ca.created_at, -- PŘIDÁNO ZDE
        s.auto_reply,
        s.approval_required,
        s.spam_filter
      FROM connected_accounts ca
      JOIN settings s
        ON s.dashboard_user_email = ca.dashboard_user_email AND s.connected_email = ca.email
      WHERE ca.active = true
        AND (s.approval_required = true OR s.spam_filter = true)
    `);

    for (const acc of accounts) {
      console.log(`   -> Zpracovávám: ${acc.connected_email}`);
      oauth2Client.setCredentials({ refresh_token: acc.refresh_token });
      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
      
      const labelsRes = await gmail.users.labels.list({ userId: 'me' });
      let approvalLabel = labelsRes.data.labels.find(l => l.name === 'ceka-na-schvaleni');
      if (!approvalLabel) {
        approvalLabel = (await gmail.users.labels.create({
          userId: 'me', requestBody: { name: 'ceka-na-schvaleni' }
        })).data;
      }

      // --- PŘIDANÁ LOGIKA PRO FILTR PODLE DATA ---
     
      const afterTimestamp = Math.floor(new Date(acc.created_at).getTime() / 1000);
      const searchQuery = `is:unread in:inbox after:${afterTimestamp}`;
      // --- KONEC LOGIKY ---

      // Hledej nové nepřečtené v inboxu s časovým omezením
      const listResponse = await gmail.users.messages.list({ userId: 'me', q: searchQuery });
      const messages = listResponse.data.messages || [];
      if (messages.length === 0) continue;

      console.log(`      Nalezeno ${messages.length} nových zpráv.`);
      for (const msg of messages) {
        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: msg.id });
        const subject = msgResponse.data.payload.headers.find(h => h.name === 'Subject')?.value || '';

        const prompt = `Jsi AI asistent pro třídění emailů. Klasifikuj následující email. Vrať pouze JSON {"category": "spam"|"approval_required"|"routine"}. Důležité emaily od šéfa nebo klientů označ jako "approval_required". Běžné reklamy a zjevný spam "spam". Předmět: ${subject} Fragment: ${msgResponse.data.snippet}`;
        
        const geminiResult = await model.generateContent(prompt);
        const analysisText = geminiResult.response.candidates[0].content.parts[0].text;
        const analysis = JSON.parse(analysisText.replace(/```json|```/g, ''));

        if (analysis.category === 'spam' && acc.spam_filter) {
          await gmail.users.messages.modify({
            userId: 'me', id: msg.id,
            requestBody: { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] }
          });
          console.log(`         "${subject}" → SPAM`);
        } else if (analysis.category === 'approval_required' && acc.approval_required) {
          await gmail.users.messages.modify({
            userId: 'me', id: msg.id,
            requestBody: { addLabelIds: [approvalLabel.id], removeLabelIds: ['INBOX', 'UNREAD'] }
          });
          console.log(`         "${subject}" → čeká na schválení`);
        }
      }
    }
  } catch (err) {
    console.error('Došlo k chybě v automatickém workeru:', err);
  } finally {
    if (dbClient) dbClient.release();
    console.log('✅ Automatická kontrola dokončena.');
  }
}

// Endpoint, který lze stále volat ručně pro testování (např. přes UptimeRobot)
app.get('/api/trigger-worker', (req, res) => {
  if (req.query.secret !== CRON_SECRET) return res.status(401).send('Neoprávněný přístup.');
  
  // Nespustí worker okamžitě, aby se předešlo duplicitnímu běhu, pokud je cron aktivní.
  // Jen potvrdí, že by se spustil. Můžete odkomentovat, pokud chcete i manuální spouštění.
  // runEmailWorker(); 
  
  res.status(200).send('Worker je aktivní a spouští se automaticky na serveru.');
});

// Automatické spouštění každých 15 minut
cron.schedule('*/15 * * * *', () => {
  runEmailWorker();
});



// --- ADMIN SEKCE ---
// Middleware pro ověření, zda je uživatel admin
const isAdmin = async (req, res, next) => {
    // V reálné aplikaci byste ověřovali JWT token z hlavičky Authorization
    // Pro jednoduchost teď budeme kontrolovat roli podle emailu v query
    const { dashboardUserEmail } = req.query;
    if (!dashboardUserEmail) {
        return res.status(401).json({ success: false, message: 'Chybí autentizace.' });
    }

    let client;
    try {
        client = await pool.connect();
        const r = await client.query('SELECT role FROM dashboard_users WHERE email = $1', [dashboardUserEmail]);
        if (r.rowCount > 0 && r.rows[0].role === 'admin') {
            next(); // Uživatel je admin, pokračuj
        } else {
            res.status(403).json({ success: false, message: 'Přístup odepřen.' });
        }
    } catch (e) {
        res.status(500).json({ success: false, message: 'Chyba serveru.' });
    } finally {
        if (client) client.release();
    }
};

// Endpoint pro načtení všech uživatelů, chráněný isAdmin middlewarem
app.get('/api/admin/users', isAdmin, async (req, res) => {
   let client;
    try {
        client = await pool.connect();
        const { search, role } = req.query;

        // Načtení statistik
        const statsResult = await client.query(`
            SELECT
                (SELECT COUNT(*) FROM dashboard_users) AS total_users,
                (SELECT COUNT(*) FROM dashboard_users WHERE plan != 'Starter') AS paying_users,
                ((SELECT COUNT(*) FROM connected_accounts) + (SELECT COUNT(*) FROM custom_accounts)) AS connected_emails,
                (SELECT SUM(ai_actions_used) FROM usage_counters WHERE period_start = date_trunc('month', NOW()::date)) AS ai_this_month
        `);

        // Načtení seznamu uživatelů s filtrováním
        let usersQuery = 'SELECT email, name, plan, role, created_at FROM dashboard_users';
        const params = [];
        const conditions = [];

        if (search) {
            params.push(`%${search}%`);
            conditions.push(`(name ILIKE $${params.length} OR email ILIKE $${params.length})`);
        }
        if (role && role !== 'all') {
            params.push(role);
            conditions.push(`role = $${params.length}`);
        }

        if (conditions.length > 0) {
            usersQuery += ' WHERE ' + conditions.join(' AND ');
        }
        usersQuery += ' ORDER BY created_at DESC';

        const usersResult = await client.query(usersQuery, params);
        
        res.json({ 
            success: true, 
            stats: {
                totalUsers: statsResult.rows[0].total_users || 0,
                payingUsers: statsResult.rows[0].paying_users || 0,
                connectedEmails: statsResult.rows[0].connected_emails || 0,
                aiActionsThisMonth: statsResult.rows[0].ai_this_month || 0
            },
            users: usersResult.rows 
        });
    } catch (e) {
        console.error('Chyba při načítání uživatelů:', e);
        res.status(500).json({ success: false, message: 'Nepodařilo se načíst uživatele.' });
    } finally {
        if (client) client.release();
    }
});

// Endpoint pro úpravu uživatele
app.put('/api/admin/users/:email', isAdmin, async (req, res) => {
    const targetEmail = req.params.email;
    const { name, role } = req.body;
    
    if (!name || !role) {
        return res.status(400).json({ success: false, message: 'Chybí jméno nebo role.' });
    }
    
    let client;
    try {
        client = await pool.connect();
        await client.query(
            'UPDATE dashboard_users SET name = $1, role = $2 WHERE email = $3',
            [name, role, targetEmail]
        );
        res.json({ success: true, message: 'Uživatel byl aktualizován.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Aktualizace selhala.' });
    } finally {
        if (client) client.release();
    }
});



// Endpoint pro smazání uživatele
app.delete('/api/admin/users/:email', isAdmin, async (req, res) => {
    const targetEmail = req.params.email;
    const { dashboardUserEmail } = req.query; // Admin, který provádí akci

    if (targetEmail.toLowerCase() === dashboardUserEmail.toLowerCase()) {
        return res.status(400).json({ success: false, message: 'Nemůžete smazat sami sebe.' });
    }
    
    let client;
    try {
        client = await pool.connect();
        // Díky 'ON DELETE CASCADE' v databázi se smažou i všechna propojená data (účty, FAQ, atd.)
        await client.query('DELETE FROM dashboard_users WHERE email = $1', [targetEmail]);
        res.json({ success: true, message: 'Uživatel byl smazán.' });
    } catch (e) {
        res.status(500).json({ success: false, message: 'Smazání selhalo.' });
    } finally {
        if (client) client.release();
    }
});


setupDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`✅ Backend server běží na portu ${PORT}`);
    });
});


















































