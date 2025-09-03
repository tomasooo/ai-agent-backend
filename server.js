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






// ENDPOINT PRO ODPOJENÍ ÚČTU
app.post('/api/oauth/google/revoke', async (req, res) => {
    let client; // Definujeme klienta zde
    try {
        const { email } = req.body;
        client = await pool.connect();
        
        const result = await client.query('SELECT refresh_token FROM users WHERE email = $1', [email]);
        const refreshToken = result.rows[0]?.refresh_token;

        if (refreshToken) {
            await oauth2Client.revokeToken(refreshToken);
            console.log(`Token pro email ${email} byl úspěšně zneplatněn u Googlu.`);
            
            await client.query('DELETE FROM users WHERE email = $1', [email]);
            console.log(`Záznam pro ${email} byl smazán z databáze.`);
        }
        
        res.status(200).json({ success: true, message: "Účet byl úspěšně odpojen." });

    } catch (error) {
        console.error("Chyba při zneplatnění tokenu:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se odpojit účet." });
    } finally {
        // TATO ČÁST BYLA PŘIDÁNA
        // Vždy uvolní spojení s databází
        if (client) {
            client.release();
        }
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
    // Jednoduché zabezpečení, aby endpoint nemohl spustit kdokoliv
    if (req.query.secret !== CRON_SECRET) {
        return res.status(401).send('Neoprávněný přístup.');
    }

    console.log('Externí Cron Job spuštěn, zahajuji kontrolu emailů...');
    res.status(202).send('Kontrola emailů byla zahájena na pozadí.'); // Okamžitě odpovíme, aby cron nečekal





    
    // Zde je kompletní logika z původního souboru worker.js
    let dbClient;
    try {
        dbClient = await pool.connect();
        const { rows: users } = await dbClient.query('SELECT * FROM users JOIN settings ON users.email = settings.email');
        for (const user of users) {
            console.log(`Zpracovávám emaily pro: ${user.email}`);
            oauth2Client.setCredentials({ refresh_token: user.refresh_token });
            const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
            
            let labelsRes = await gmail.users.labels.list({ userId: 'me' });
            let approvalLabel = labelsRes.data.labels.find(l => l.name === 'ceka-na-schvaleni');
            if (!approvalLabel) {
                approvalLabel = (await gmail.users.labels.create({ userId: 'me', requestBody: { name: 'ceka-na-schvaleni' } })).data;
            }

            const listResponse = await gmail.users.messages.list({ userId: 'me', q: 'is:unread in:inbox' });
            const messages = listResponse.data.messages || [];

            for (const msg of messages) {
                const msgResponse = await gmail.users.messages.get({ userId: 'me', id: msg.id });
                const subject = msgResponse.data.payload.headers.find(h => h.name === 'Subject')?.value || '';
                const prompt = `Jsi AI asistent pro třídění emailů. Klasifikuj následující email. Vrať pouze JSON objekt s klíčem "category", který může mít jednu z hodnot: "spam", "approval_required", "routine". Důležité emaily od šéfa nebo klientů označ jako "approval_required". Běžné reklamy a zjevný spam označ jako "spam". Vše ostatní je "routine".\n\nPředmět: ${subject}\nFragment: ${msgResponse.data.snippet}`;
                
                const geminiResult = await model.generateContent(prompt);
                const analysisText = geminiResult.response.candidates[0].content.parts[0].text;
                const analysis = JSON.parse(analysisText.replace(/```json|```/g, ''));

                if (analysis.category === 'spam' && user.spam_filter) {
                    await gmail.users.messages.modify({ userId: 'me', id: msg.id, requestBody: { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] } });
                    console.log(`Email "${subject}" označen jako SPAM.`);
                } else if (analysis.category === 'approval_required' && user.approval_required) {
                    await gmail.users.messages.modify({ userId: 'me', id: msg.id, requestBody: { addLabelIds: [approvalLabel.id], removeLabelIds: ['INBOX'] } });
                    console.log(`Email "${subject}" přesunut ke schválení.`);
                }
            }
        }
    } catch (error) {
        console.error('Došlo k chybě v automatickém workeru:', error);
    } finally {
        if (dbClient) { // Uvolníme, jen pokud existuje
        dbClient.release();
    }
    console.log('Automatická kontrola dokončena.');
    }





    
});


setupDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`✅ Backend server běží na portu ${PORT}`);
    });
});


