// server.js
const express = require('express');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const { Pool } = require('pg'); // Ovladač pro PostgreSQL
const { google } = require('googleapis'); // PŘIDÁNO: Knihovna pro Google API
const { VertexAI } = require('@google-cloud/vertexai');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const jwt = require('jsonwebtoken'); // pokud chceš tokeny; není nutné pro toto minimum
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';


const app = express();
const PORT = process.env.PORT || 3000;

// Načtení proměnných prostředíconst cors = require('cors');
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
                plan VARCHAR(50) DEFAULT 'Free',
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await client.query(`
  ALTER TABLE dashboard_users
    ADD COLUMN IF NOT EXISTS password_hash TEXT,
    ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT false,
    ADD COLUMN IF NOT EXISTS verification_token TEXT
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
        
        // Smazání staré tabulky users, pokud existuje (jen pro přechod)
        // await client.query(`DROP TABLE IF EXISTS users;`);


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
                FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE,
                FOREIGN KEY (connected_email) REFERENCES connected_accounts(email) ON DELETE CASCADE
            );
        `);


        await client.query(`
  CREATE TABLE IF NOT EXISTS plans (
    code VARCHAR(50) PRIMARY KEY,     -- např. 'Starter', 'Professional', 'Enterprise'
    label VARCHAR(100) NOT NULL,      -- zobrazovací název
    max_accounts INT NOT NULL,        -- max počet připojených účtů
    monthly_ai_actions INT NOT NULL   -- měsíční limit na AI akce (analyzuj + odeslání odpovědi)
  );
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


        
        console.log("✅ Databázové tabulky pro víceuživatelský provoz jsou připraveny.");
    } catch (err) {
        console.error('Chyba při nastavování databází:', err);
    } finally {
        if (client) {
            client.release();
        }
    }
}





// Nastavení CORS


const DEFAULT_ALLOWED = [
  'https://ai-agent-frontend-9nrf.onrender.com', // Render frontend
  'http://localhost:5500',                        // local dev
  'http://127.0.0.1:5500',                        // local dev
];

// možnost doplnit další origins přes ENV (ALLOWED_ORIGINS="url1,url2")
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

if (process.env.FRONTEND_URL) ALLOWED_ORIGINS.push(process.env.FRONTEND_URL);

const ORIGINS = Array.from(new Set([...DEFAULT_ALLOWED, ...ALLOWED_ORIGINS]));

console.log('CORS allowed origins:', ORIGINS);

const corsOptions = {
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // např. curl nebo server-side request
    return ORIGINS.includes(origin)
      ? cb(null, true)
      : cb(new Error('Not allowed by CORS: ' + origin));
  },
  methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: false, // dej true jen pokud používáš cookies
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));

app.use(bodyParser.json());
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
        const payload = ticket.getPayload(); // obsahuje email + name

        client = await pool.connect();
        await client.query(
            `INSERT INTO dashboard_users (email, name)
             VALUES ($1, $2)
             ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name`,
            [payload.email, payload.name]
        );

        res.status(200).json({ success: true, user: payload });
    } catch (error) {
        console.error("Chyba při ověřování přihlašovacího tokenu:", error);
        res.status(401).json({ success: false, message: 'Ověření selhalo.' });
    } finally {
        if (client) client.release();
    }
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





app.post('/api/templates/render', async (req, res) => {
  try {
    const { dashboardUserEmail, templateId, content, variables, context } = req.body || {};
    if (!dashboardUserEmail || (!templateId && !content)) {
      return res.status(400).json({ success:false, message:'Chybí data' });
    }

    const client = await pool.connect();
    let tplText = content;
    if (!tplText) {
      const r = await client.query(
        'SELECT content FROM templates WHERE id=$1 AND dashboard_user_email=$2',
        [templateId, dashboardUserEmail]
      );
      if (r.rowCount === 0) {
        client.release();
        return res.status(404).json({ success:false, message:'Šablona nenalezena' });
      }
      tplText = r.rows[0].content;
    }

    // 1) Nahrazení manuálních proměnných {{var}}
    let filled = String(tplText);
    if (variables && typeof variables === 'object') {
      for (const [key, val] of Object.entries(variables)) {
        const re = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
        filled = filled.replace(re, val ?? '');
      }
    }

/* === 1.5) AI doplnění chybějících {{proměnných}} z emailu (rozšířená verze) === */
try {
  // 1) Seznam chybějících klíčů
  const missingKeys = Array.from(new Set(
    [...filled.matchAll(/{{\s*([a-zA-Z0-9_]+)\s*}}/g)].map(m => m[1])
  ));

  if (missingKeys.length) {
    const emailBody = context?.emailBody || '';
    const analysis  = context?.analysis  || {};
    const settings  = context?.settings  || {};
    const meta      = context?.meta      || {}; // { subject, from, date }

    // 2) Prompt se speciálními pravidly pro tvoje klíče
const promptVars = `Jsi asistent pro doplňování proměnných v šabloně emailu.
Máš seznam proměnných, metadata a text původního emailu. Pokud informaci NELZE spolehlivě vyčíst,
dej null nebo prázdný řetězec. NEVYMÝŠLEJ nesmysly.

Vrať POUZE JSON objekt { "klic": "hodnota", ... } bez dalšího textu.

Proměnné k doplnění:
${JSON.stringify(missingKeys)}

Metadata (např. subject, from):
${JSON.stringify(meta).slice(0,1000)}

Analýza (pokud je k dispozici):
${JSON.stringify(analysis).slice(0,1200)}

Text emailu:
${emailBody.slice(0, 4000)}

Speciální pravidla a mapování (CZ):
- recipientName: vytvoř vhodné ČESKÉ oslovení ("paní Nováková"/"pane Dvořáku") podle „From:“ nebo podpisu.
- senderName: když nejde zjistit, nech null (doplní se ze signature aplikace).
- company: název firmy z podpisu, From: nebo domény; uveď jen název (bez s.r.o., a.s. pokud to dává smysl).
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
- meetingDate: pokud je v emailu explicitní termín schůzky, vrať jej; jinak nech prázdné (nedopočítávej).
- ourNextStep / theirNextStep: jeden krátký jasný krok, co uděláme my / co mají udělat oni.
- ourDeadline / theirDeadline / deadline: pokud je v emailu datum/termín, vrať jej; formátuj jako "7. 9. 2025" nebo "7. 9. 2025 14:00".
- Hodnoty piš stručně, bez uvozovek navíc a bez vysvětlování.`;


      

    const ai = await model.generateContent(promptVars);
    const raw = ai?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    const inferred = JSON.parse(raw.replace(/```json|```/g, '').trim() || '{}');


if (!inferred?.meetingDate && inferred?.slot1) {
  inferred.meetingDate = inferred.slot1; // použij první slot
}
      
    // 3) Defaultní fallbacky (když AI/zdroj nic nedá)
    const DEFAULTS = {
      solutionOptionA: 'výměna za nový kus',
  solutionOptionB: 'refundace po vrácení zboží',
  kpi: 'konverzní poměr',
  timeframe: '',
  // nové:
  ourNextStep: '',
  ourDeadline: '',
  theirNextStep: '',
  theirDeadline: '',
  meetingDate: '',
  deadline: ''
    };

    // fallback pro senderName ze signature (první řádek)
    if ((inferred?.senderName == null || inferred.senderName === '') && settings?.signature) {
      const firstLine = (settings.signature || '').split('\n')[0].trim().replace(/^[-–—\s]*/, '');
      if (firstLine) inferred.senderName = firstLine;
    }

    // 4) Aplikace doplněných hodnot do šablony + defaulty
    for (const key of missingKeys) {
      let val = (inferred?.[key] ?? '').toString().trim();

      if (!val && Object.prototype.hasOwnProperty.call(DEFAULTS, key)) {
        val = DEFAULTS[key];
      }

      if (val) {
        const re = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
        filled = filled.replace(re, val);
      }
    }
  }
} catch (err) {
  console.warn('AI variable fill failed, skipping.', err?.message);
}
/* === /1.5) === */


      

    // 2) Najdi AI sloty [[AI: ...]]
    const aiSlotRegex = /\[\[\s*AI\s*:(.*?)\]\]/gs;
    const slots = [...filled.matchAll(aiSlotRegex)];
    if (slots.length) {
      // vyrob společný kontext
      const emailBody = context?.emailBody || '';
      const analysis  = context?.analysis  || {};
      const settings  = context?.settings  || {};

      // postupně dopočítej každé místo
      for (const m of slots) {
        const whole  = m[0];
        const instr  = (m[1] || '').trim();

        const prompt = `Úkol: ${instr}
---
Kontext emailu (text):
${emailBody.slice(0, 4000)}

Analýza (JSON):
${JSON.stringify(analysis).slice(0, 2000)}

Preferovaný tón: ${settings.tone || 'Formální'}
Délka: ${settings.length || 'Střední (1 odstavec)'}
Podpis (pokud relevantní přidej až na konec): ${settings.signature || ''}

Odpověz pouze textem bez dalších vysvětlivek.`;

        const out = await model.generateContent(prompt);
        const aiText = out?.response?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        filled = filled.replace(whole, aiText.trim());
      }
    }

    client.release();
    return res.json({ success:true, rendered: filled });
  } catch (e) {
    console.error('TEMPLATE RENDER ERROR', e);
    return res.status(500).json({ success:false, message:'Render selhal' });
  }
});







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
    const r = await client.query(
      `UPDATE connected_accounts
       SET active = $1
       WHERE email = $2 AND dashboard_user_email = $3`,
      [active, email, dashboardUserEmail]
    );
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
      'SELECT email, name, password_hash FROM dashboard_users WHERE email = $1',
      [email]
    );
    if (r.rowCount === 0 || !r.rows[0].password_hash) {
      return res.status(401).json({ success: false, message: 'Nesprávný email nebo heslo.' });
    }
    const ok = await require('bcryptjs').compare(password, r.rows[0].password_hash);
    if (!ok) return res.status(401).json({ success: false, message: 'Nesprávný email nebo heslo.' });

    return res.json({ success: true, user: { email: r.rows[0].email, name: r.rows[0].name }});
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
  const r = await client.query(`
    SELECT COUNT(*)::INT AS c FROM connected_accounts WHERE dashboard_user_email = $1
  `, [dashboardUserEmail]);
  const count = r.rows[0].c;
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
    const r = await client.query(
      'SELECT email, active FROM connected_accounts WHERE dashboard_user_email = $1 ORDER BY created_at ASC',
      [dashboardUserEmail]
    );

    // „nový“ tvar pro FE: accounts: [{email, active}]
    const accounts = r.rows.map(row => ({ email: row.email, active: !!row.active }));
    // „starý“ fallback tvar jen pro /api/accounts/list: emails: [...]
    const emails = r.rows.map(row => row.email);

    // Rozlišíme podle cesty (aby FE fallback pořád fungoval)
    if (req.path.endsWith('/list')) {
      return res.json({ success: true, emails });
    }
    return res.json({ success: true, accounts });
  } catch (err) {
    console.error('Chyba při čtení connected_accounts:', err);
    return res.status(500).json({ success: false, message: 'Nepodařilo se načíst připojené účty.' });
  } finally {
    if (client) client.release();
  }
}

app.get('/api/accounts', listConnectedAccountsHandler);
app.get('/api/accounts/list', listConnectedAccountsHandler); // kvůli fallbacku z FE





// ENDPOINT PRO ODPOJENÍ ÚČTU
app.post('/api/oauth/google/revoke', async (req, res) => {
    let client;
  try {
    const { email, dashboardUserEmail } = req.body;
    if (!email || !dashboardUserEmail) {
      return res.status(400).json({ success: false, message: 'Chybí email nebo dashboardUserEmail.' });
    }

    client = await pool.connect();
    const result = await client.query(
      'SELECT refresh_token FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
      [email, dashboardUserEmail]
    );
    const refreshToken = result.rows[0]?.refresh_token;

    if (refreshToken) {
      await oauth2Client.revokeToken(refreshToken);
      console.log(`Token pro ${email} zneplatněn u Googlu.`);
    }

    // Smazáním z connected_accounts (FK v settings je ON DELETE CASCADE)
    await client.query(
      'DELETE FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
      [email, dashboardUserEmail]
    );

    return res.status(200).json({ success: true, message: 'Účet byl úspěšně odpojen.' });
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

        const replySubject = originalSubject.startsWith('Re: ') ? originalSubject : `Re: ${originalSubject}`;
        const raw = Buffer.from([
            `From: ${email}`,
            `To: ${originalFrom}`,
            `Subject: ${replySubject}`,
            `In-Reply-To: ${originalMessageId}`,
            `References: ${originalReferences} ${originalMessageId}`,
            'Content-Type: text/plain; charset=utf-8',
            '',
            replyBody
        ].join('\n')).toString('base64url');

        await gmail.users.messages.send({
            userId: 'me',
            requestBody: { raw, threadId: msgResponse.data.threadId }
        });

        res.json({ success: true, message: "Email byl úspěšně odeslán." });
    } catch (error) {
        console.error("Chyba při odesílání emailu:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se odeslat email." });
    }
});








// UPRAVENÝ ENDPOINT PRO NAČTENÍ EMAILŮ S FILTROVÁNÍM
app.get('/api/gmail/emails', async (req, res) => {
  try {
    const { email, dashboardUserEmail, status, period, searchQuery } = req.query;
    if (!email || !dashboardUserEmail) {
      return res.status(400).json({ success: false, message: "Chybí email nebo dashboardUserEmail." });
    }

    const db = await pool.connect();
    const acc = await db.query(
      'SELECT refresh_token, active FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
      [email, dashboardUserEmail]
    );
    db.release();

    if (acc.rowCount === 0) {
      return res.status(404).json({ success: false, message: "Účet nenalezen." });
    }
    if (acc.rows[0].active === false) {
      return res.status(403).json({ success: false, message: "Tento účet je neaktivní." });
    }

    const refreshToken = acc.rows[0].refresh_token;
        if (!refreshToken) {
            return res.status(404).json({ success: false, message: "Pro tento email u tohoto uživatele nebyl nalezen token." });
        }

        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const queryParts = [];
        if (status === 'unread') queryParts.push('is:unread');
        if (status === 'spam') queryParts.push('in:spam');
        if (period === 'today') queryParts.push('newer_than:1d');
        if (period === 'week') queryParts.push('newer_than:7d');
        if (searchQuery) queryParts.push(searchQuery);
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
                userId: 'me', id: m.id, format: 'metadata', metadataHeaders: ['Subject', 'From', 'Date']
            });
            const headers = mr.data.payload.headers;
            const getHeader = (n) => headers.find(h => h.name === n)?.value || '';
            return {
                id: m.id,
                snippet: mr.data.snippet,
                sender: getHeader('From'),
                subject: getHeader('Subject'),
                date: getHeader('Date')
            };
        }));

        res.json({ success: true, emails, total: listResponse.data.resultSizeEstimate });
    } catch (error) {
        console.error("Chyba při načítání emailů:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst emaily." });
    }
});









// === NOVÝ ENDPOINT PRO ANALÝZU EMAILU POMOCÍ GEMINI ===
app.post('/api/gmail/analyze-email', async (req, res) => {
    try {
        const { dashboardUserEmail, email, messageId } = req.body;
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

        const prompt = `Jsi profesionální emailový asistent. Analyzuj následující email. V odpovědi vrať JSON s klíči "summary", "sentiment", "suggested_reply".
Tón: ${settings.tone}
Délka: ${settings.length}
Podpis: "${settings.signature}"

Email:
---
${emailBody.substring(0, 3000)}`;

        const geminiResult = await model.generateContent(prompt);
        const text = geminiResult.response.candidates[0].content.parts[0].text;
        const cleaned = text.replace(/```json|```/g, '');
        res.json({ success: true, analysis: JSON.parse(cleaned), emailBody });
    } catch (error) {
        console.error("Chyba při analýze emailu:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se analyzovat email." });
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


// === NOVÝ ENDPOINT, KTERÝ BUDE VOLAT EXTERNÍ SLUŽBA ===
app.get('/api/trigger-worker', async (req, res) => {
    if (req.query.secret !== CRON_SECRET) return res.status(401).send('Neoprávněný přístup.');
  console.log('Externí Cron Job spuštěn, zahajuji kontrolu emailů...');
  res.status(202).send('Kontrola emailů zahájena.');

  let dbClient;
  try {
    dbClient = await pool.connect();

    // Vezmeme všechny propojené schránky s jejich nastavením
    const { rows: accounts } = await dbClient.query(`
      SELECT 
        ca.email               AS connected_email,
        ca.refresh_token,
        ca.dashboard_user_email,
         ca.active,
        s.auto_reply,
        s.approval_required,
        s.spam_filter
      FROM connected_accounts ca
      LEFT JOIN settings s
        ON s.dashboard_user_email = ca.dashboard_user_email
       AND s.connected_email = ca.email
       WHERE ca.active = true 
    `);

    for (const acc of accounts) {
      console.log(`Zpracovávám: ${acc.connected_email} (uživatel: ${acc.dashboard_user_email})`);

      oauth2Client.setCredentials({ refresh_token: acc.refresh_token });
      const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

      // label "ceka-na-schvaleni"
      const labelsRes = await gmail.users.labels.list({ userId: 'me' });
      let approvalLabel = labelsRes.data.labels.find(l => l.name === 'ceka-na-schvaleni');
      if (!approvalLabel) {
        approvalLabel = (await gmail.users.labels.create({
          userId: 'me', requestBody: { name: 'ceka-na-schvaleni' }
        })).data;
      }

      // nové nepřečtené v inboxu
      const listResponse = await gmail.users.messages.list({ userId: 'me', q: 'is:unread in:inbox' });
      const messages = listResponse.data.messages || [];

      for (const msg of messages) {
        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: msg.id });
        const subject = msgResponse.data.payload.headers.find(h => h.name === 'Subject')?.value || '';

        const prompt = `Jsi AI asistent pro třídění emailů. Klasifikuj následující email. Vrať pouze JSON {"category": "spam"|"approval_required"|"routine"}.
Důležité emaily od šéfa nebo klientů označ jako "approval_required". Běžné reklamy a zjevný spam "spam".
Předmět: ${subject}
Fragment: ${msgResponse.data.snippet}`;

        const geminiResult = await model.generateContent(prompt);
        const analysisText = geminiResult.response.candidates[0].content.parts[0].text;
        const analysis = JSON.parse(analysisText.replace(/```json|```/g, ''));

        if (analysis.category === 'spam' && acc.spam_filter) {
          await gmail.users.messages.modify({
            userId: 'me', id: msg.id,
            requestBody: { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] }
          });
          console.log(`"${subject}" → SPAM`);
        } else if (analysis.category === 'approval_required' && acc.approval_required) {
          await gmail.users.messages.modify({
            userId: 'me', id: msg.id,
            requestBody: { addLabelIds: [approvalLabel.id], removeLabelIds: ['INBOX'] }
          });
          console.log(`"${subject}" → čeká na schválení`);
        }
      }
    }
  } catch (err) {
    console.error('Došlo k chybě v automatickém workeru:', err);
  } finally {
    if (dbClient) dbClient.release();
    console.log('Automatická kontrola dokončena.');
  }
});


setupDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`✅ Backend server běží na portu ${PORT}`);
    });
});



















