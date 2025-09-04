// server.js
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg'); // Ovladač pro PostgreSQL
const { google } = require('googleapis'); // PŘIDÁNO: Knihovna pro Google API
const { VertexAI } = require('@google-cloud/vertexai');



const app = express();
const PORT = process.env.PORT || 3000;

// Načtení proměnných prostředí
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

        // 2. Tabulka pro emaily, které si uživatelé připojí (původní "users")
        // PŘIDALI JSME dashboard_user_email, který je cizím klíčem
        await client.query(`
            CREATE TABLE IF NOT EXISTS connected_accounts (
                email VARCHAR(255) PRIMARY KEY,
                refresh_token TEXT NOT NULL,
                dashboard_user_email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE
            );
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
const corsOptions = { origin: FRONTEND_URL, optionsSuccessStatus: 200 };
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
      'SELECT email FROM connected_accounts WHERE dashboard_user_email = $1 ORDER BY created_at ASC',
      [dashboardUserEmail]
    );
    const emails = r.rows.map(row => row.email);
    return res.json({ success: true, emails });
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
        const r = await db.query(
            'SELECT refresh_token FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
            [email, dashboardUserEmail]
        );
        db.release();
        const refreshToken = r.rows[0]?.refresh_token;
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
        res.json({ success: true, analysis: JSON.parse(cleaned) });
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
        s.auto_reply,
        s.approval_required,
        s.spam_filter
      FROM connected_accounts ca
      LEFT JOIN settings s
        ON s.dashboard_user_email = ca.dashboard_user_email
       AND s.connected_email = ca.email
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





