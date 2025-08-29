// server.js
// =================================================================
// === Importy a základní nastavení ================================
// =================================================================

const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg'); // Ovladač pro PostgreSQL
const { google } = require('googleapis'); // Knihovna pro Google API
const { VertexAI } = require('@google-cloud/vertexai');

const app = express();
const PORT = process.env.PORT || 3000;

// =================================================================
// === Načtení proměnných prostředí ================================
// =================================================================

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;
const DATABASE_URL = process.env.DATABASE_URL;
const PROJECT_ID = process.env.GOOGLE_PROJECT_ID;
const LOCATION = 'us-central1';
const CRON_SECRET = process.env.CRON_SECRET;
const SERVER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${SERVER_URL}/api/oauth/google/callback`;

// Kontrola existence proměnných
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FRONTEND_URL || !DATABASE_URL || !PROJECT_ID || !CRON_SECRET) {
    console.error("Chyba: Chybí potřebné proměnné prostředí! Zkontrolujte nastavení na Renderu.");
    process.exit(1);
}

// =================================================================
// === Inicializace služeb (Google AI, Databáze) ===================
// =================================================================

// Inicializace Vertex AI (Gemini)
const vertex_ai = new VertexAI({ project: PROJECT_ID, location: LOCATION });
const model = vertex_ai.getGenerativeModel({
    model: 'gemini-1.5-flash',
});

// Nastavení databázového spojení
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Nutné pro Render
});

// =================================================================
// === Databázová struktura pro víceuživatelský provoz =============
// =================================================================

async function setupDatabase() {
    let client;
    try {
        client = await pool.connect();

        // Tabulka pro uživatele, kteří se přihlašují do naší aplikace (uživatelé dashboardu)
        await client.query(`
            CREATE TABLE IF NOT EXISTS dashboard_users (
                email VARCHAR(255) PRIMARY KEY,
                name VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Tabulka pro emailové účty, které si uživatelé připojí
        await client.query(`
            CREATE TABLE IF NOT EXISTS connected_accounts (
                email VARCHAR(255) PRIMARY KEY,
                refresh_token TEXT NOT NULL,
                dashboard_user_email VARCHAR(255) NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (dashboard_user_email) REFERENCES dashboard_users(email) ON DELETE CASCADE
            );
        `);

        // Tabulka pro nastavení, vázaná na konkrétního uživatele a jeho připojený účet
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

// =================================================================
// === Express konfigurace a Middleware ============================
// =================================================================

const corsOptions = { origin: FRONTEND_URL, optionsSuccessStatus: 200 };
app.use(cors(corsOptions));
app.use(bodyParser.json());

// Klient pro ověření PŘIHLAŠOVACÍHO tokenu
const loginClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Klient pro PROPOJENÍ a ODPOJENÍ účtu (potřebuje Client Secret)
const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI);


/**
 * Middleware pro ověření, zda přihlášený uživatel (dashboard_user_email)
 * má oprávnění přistupovat k datům připojeného účtu (connected_email).
 */
const verifyOwnership = async (req, res, next) => {
    const dashboardUserEmail = req.body.dashboard_user_email || req.query.dashboard_user_email;
    const connectedEmail = req.body.email || req.query.email;

    if (!dashboardUserEmail || !connectedEmail) {
        return res.status(400).json({ success: false, message: "Chybí identifikace uživatele nebo účtu." });
    }

    try {
        const client = await pool.connect();
        const result = await client.query(
            'SELECT 1 FROM connected_accounts WHERE email = $1 AND dashboard_user_email = $2',
            [connectedEmail, dashboardUserEmail]
        );
        client.release();

        if (result.rows.length === 0) {
            return res.status(403).json({ success: false, message: "Přístup odepřen." });
        }
        next();
    } catch (error) {
        console.error("Chyba při ověřování vlastnictví:", error);
        res.status(500).json({ success: false, message: "Chyba serveru při ověřování." });
    }
};


// =================================================================
// === API Endpoints ===============================================
// =================================================================

// --- Správa uživatelů a účtů ---

app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await loginClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        
        const client = await pool.connect();
        await client.query(
            'INSERT INTO dashboard_users (email, name) VALUES ($1, $2) ON CONFLICT (email) DO UPDATE SET name = $2',
            [payload.email, payload.name]
        );
        client.release();
        
        console.log(`Uživatel dashboardu přihlášen/registrován: ${payload.name} (${payload.email})`);
        res.status(200).json({ success: true, user: payload });
    } catch (error) {
        console.error("Chyba při ověřování přihlašovacího tokenu:", error);
        res.status(401).json({ success: false, message: 'Ověření selhalo.' });
    }
});

app.get('/api/oauth/google/callback', async (req, res) => {
    try {
        const code = req.query.code;
        const state = req.query.state;

        if (!code || !state) {
            throw new Error('Autorizační kód nebo stavový parametr (state) chybí.');
        }

        const dashboardUserEmail = decodeURIComponent(state);
        const { tokens } = await oauth2Client.getToken(code);
        const ticket = await loginClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const connectedEmail = payload.email;

        if (tokens.refresh_token) {
            console.log(`Získán Refresh Token pro ${connectedEmail}. Ukládám pro uživatele ${dashboardUserEmail}.`);
            const client = await pool.connect();
            await client.query(
                'INSERT INTO connected_accounts (email, refresh_token, dashboard_user_email) VALUES ($1, $2, $3) ON CONFLICT (email) DO UPDATE SET refresh_token = $2, dashboard_user_email = $3',
                [connectedEmail, tokens.refresh_token, dashboardUserEmail]
            );
            client.release();
        }
        
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=success&new-email=${connectedEmail}`);

    } catch (error) {
        console.error("Chyba při zpracování OAuth callbacku:", error.message);
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=error`);
    }
});

app.get('/api/user/accounts', async (req, res) => {
    try {
        const { dashboard_user_email } = req.query;
        if (!dashboard_user_email) {
            return res.status(400).json({ success: false, message: "Chybí email uživatele." });
        }
        
        const client = await pool.connect();
        const result = await client.query('SELECT email FROM connected_accounts WHERE dashboard_user_email = $1 ORDER BY created_at ASC', [dashboard_user_email]);
        client.release();

        const emails = result.rows.map(row => row.email);
        res.json({ success: true, emails: emails });
    } catch (error) {
        console.error("Chyba při načítání účtů:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst připojené účty." });
    }
});

app.post('/api/oauth/google/revoke', verifyOwnership, async (req, res) => {
    let client;
    try {
        const { email } = req.body;
        client = await pool.connect();
        
        const result = await client.query('SELECT refresh_token FROM connected_accounts WHERE email = $1', [email]);
        const refreshToken = result.rows[0]?.refresh_token;

        if (refreshToken) {
            await oauth2Client.revokeToken(refreshToken);
            console.log(`Token pro ${email} zneplatněn u Googlu.`);
            
            await client.query('DELETE FROM connected_accounts WHERE email = $1', [email]);
            console.log(`Záznam pro ${email} smazán z databáze.`);
        }
        
        res.status(200).json({ success: true, message: "Účet byl úspěšně odpojen." });
    } catch (error) {
        console.error("Chyba při odpojování účtu:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se odpojit účet." });
    } finally {
        if (client) client.release();
    }
});

// --- Práce s emaily ---

app.get('/api/gmail/emails', verifyOwnership, async (req, res) => {
    try {
        const { email, status, period, searchQuery } = req.query;

        const client = await pool.connect();
        const result = await client.query('SELECT refresh_token FROM connected_accounts WHERE email = $1', [email]);
        client.release();
        const refreshToken = result.rows[0]?.refresh_token;
        
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const queryParts = ['in:inbox'];
        if (status === 'unread') queryParts.push('is:unread');
        if (status === 'spam') { queryParts.splice(0, 1, 'in:spam'); }
        if (period === 'today') queryParts.push('newer_than:1d');
        if (period === 'week') queryParts.push('newer_than:7d');
        if (searchQuery) queryParts.push(searchQuery);
        
        const finalQuery = queryParts.join(' ');

        const listResponse = await gmail.users.messages.list({ userId: 'me', maxResults: 20, q: finalQuery });
        const messageIds = listResponse.data.messages || [];

        if (messageIds.length === 0) {
            return res.json({ success: true, emails: [], total: 0 });
        }

        const emailPromises = messageIds.map(async (msg) => {
            const msgResponse = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'metadata', metadataHeaders: ['Subject', 'From', 'Date'] });
            const headers = msgResponse.data.payload.headers;
            const getHeader = (name) => headers.find(h => h.name === name)?.value || '';
            return {
                id: msg.id, snippet: msgResponse.data.snippet, sender: getHeader('From'),
                subject: getHeader('Subject'), date: getHeader('Date')
            };
        });

        const emails = await Promise.all(emailPromises);
        res.json({ success: true, emails, total: listResponse.data.resultSizeEstimate });

    } catch (error) {
        console.error("Chyba při načítání emailů:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst emaily." });
    }
});

app.post('/api/gmail/send-reply', verifyOwnership, async (req, res) => {
    try {
        const { email, messageId, replyBody } = req.body;
        
        const dbClient = await pool.connect();
        const result = await dbClient.query('SELECT refresh_token FROM connected_accounts WHERE email = $1', [email]);
        dbClient.release();
        const refreshToken = result.rows[0]?.refresh_token;
        
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: messageId });
        
        const originalHeaders = msgResponse.data.payload.headers;
        const originalSubject = originalHeaders.find(h => h.name.toLowerCase() === 'subject').value;
        const originalFrom = originalHeaders.find(h => h.name.toLowerCase() === 'from').value;
        const originalMessageId = originalHeaders.find(h => h.name.toLowerCase() === 'message-id').value;
        
        const replySubject = originalSubject.startsWith('Re: ') ? originalSubject : `Re: ${originalSubject}`;
        const mailParts = [
            `From: ${email}`, `To: ${originalFrom}`, `Subject: ${replySubject}`,
            `In-Reply-To: ${originalMessageId}`, `References: ${originalMessageId}`,
            'Content-Type: text/plain; charset=utf-8', '', replyBody
        ];
        const rawMessage = Buffer.from(mailParts.join('\n')).toString('base64url');

        await gmail.users.messages.send({
            userId: 'me',
            requestBody: { raw: rawMessage, threadId: msgResponse.data.threadId }
        });

        res.json({ success: true, message: "Email byl úspěšně odeslán." });

    } catch (error) {
        console.error("Chyba při odesílání emailu:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se odeslat email." });
    }
});

app.post('/api/gmail/analyze-email', verifyOwnership, async (req, res) => {
    try {
        const { dashboard_user_email, email: connected_email, messageId } = req.body;

        const dbClient = await pool.connect();
        const userResult = await dbClient.query('SELECT refresh_token FROM connected_accounts WHERE email = $1', [connected_email]);
        let settingsResult = await dbClient.query('SELECT * FROM settings WHERE connected_email = $1 AND dashboard_user_email = $2', [connected_email, dashboard_user_email]);
        
        let settings = settingsResult.rows[0];
        if (!settings) {
            await dbClient.query('INSERT INTO settings (dashboard_user_email, connected_email) VALUES ($1, $2) ON CONFLICT DO NOTHING', [dashboard_user_email, connected_email]);
            settingsResult = await dbClient.query('SELECT * FROM settings WHERE connected_email = $1 AND dashboard_user_email = $2', [connected_email, dashboard_user_email]);
            settings = settingsResult.rows[0];
        }
        dbClient.release();
        
        const refreshToken = userResult.rows[0]?.refresh_token;
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: messageId });
        
        let emailBody = '';
        if (msgResponse.data.payload.parts) {
            const part = msgResponse.data.payload.parts.find(p => p.mimeType === 'text/plain');
            if (part && part.body.data) emailBody = Buffer.from(part.body.data, 'base64').toString('utf-8');
        } else if (msgResponse.data.payload.body.data) {
            emailBody = Buffer.from(msgResponse.data.payload.body.data, 'base64').toString('utf-8');
        }

        const prompt = `Jsi profesionální emailový asistent... (zde váš kompletní prompt) ... Tón: ${settings.tone}, Délka: ${settings.length}, Podpis: "${settings.signature}" ... Email: ${emailBody.substring(0, 4000)}`;

        const geminiResult = await model.generateContent(prompt);
        const analysisText = geminiResult.response.candidates[0].content.parts[0].text;
        const cleanedText = analysisText.replace(/```json|```/g, '');
        res.json({ success: true, analysis: JSON.parse(cleanedText) });

    } catch (error) {
        console.error("Chyba při analýze emailu:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se analyzovat email." });
    }
});

// --- Správa nastavení ---

app.get('/api/settings', verifyOwnership, async (req, res) => {
    let client;
    try {
        const { dashboard_user_email, email: connected_email } = req.query;
        client = await pool.connect();
        let result = await client.query('SELECT * FROM settings WHERE dashboard_user_email = $1 AND connected_email = $2', [dashboard_user_email, connected_email]);
        
        if (result.rows.length === 0) {
            await client.query('INSERT INTO settings (dashboard_user_email, connected_email) VALUES ($1, $2)', [dashboard_user_email, connected_email]);
            result = await client.query('SELECT * FROM settings WHERE dashboard_user_email = $1 AND connected_email = $2', [dashboard_user_email, connected_email]);
        }
        
        res.json({ success: true, settings: result.rows[0] });
    } catch (error) {
        console.error("Chyba při načítání nastavení:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst nastavení." });
    } finally {
        if (client) client.release();
    }
});

app.post('/api/settings', verifyOwnership, async (req, res) => {
    let client;
    try {
        const { dashboard_user_email, email: connected_email, tone, length, signature, auto_reply, approval_required, spam_filter } = req.body;
        client = await pool.connect();
        await client.query(
            `UPDATE settings SET tone = $1, length = $2, signature = $3, auto_reply = $4, approval_required = $5, spam_filter = $6
             WHERE dashboard_user_email = $7 AND connected_email = $8`,
            [tone, length, signature, auto_reply, approval_required, spam_filter, dashboard_user_email, connected_email]
        );
        res.json({ success: true, message: "Nastavení bylo úspěšně uloženo." });
    } catch (error) {
        console.error("Chyba při ukládání nastavení:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se uložit nastavení." });
    } finally {
        if (client) client.release();
    }
});


// =================================================================
// === Automatický CRON Job ========================================
// =================================================================

app.get('/api/trigger-worker', async (req, res) => {
    if (req.query.secret !== CRON_SECRET) {
        return res.status(401).send('Neoprávněný přístup.');
    }

    console.log('CRON: Externí Job spuštěn, zahajuji kontrolu emailů pro všechny uživatele...');
    res.status(202).send('Kontrola emailů byla zahájena na pozadí.');

    let dbClient;
    try {
        dbClient = await pool.connect();
        const { rows: all_accounts } = await dbClient.query(`
            SELECT ca.email, ca.refresh_token, s.* FROM connected_accounts ca 
            JOIN settings s ON ca.email = s.connected_email AND ca.dashboard_user_email = s.dashboard_user_email
        `);
        
        for (const account of all_accounts) {
            try {
                console.log(`CRON: Zpracovávám emaily pro: ${account.email} (patří ${account.dashboard_user_email})`);
                oauth2Client.setCredentials({ refresh_token: account.refresh_token });
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
                    const subject = msgResponse.data.payload.headers.find(h => h.name.toLowerCase() === 'subject')?.value || '';
                    
                    const prompt = `Jsi AI asistent pro třídění emailů. Klasifikuj následující email. Vrať pouze JSON objekt s klíčem "category", který může mít jednu z hodnot: "spam", "approval_required", "routine". Důležité emaily od šéfa nebo klientů označ jako "approval_required". Běžné reklamy a zjevný spam označ jako "spam". Vše ostatní je "routine".\n\nPředmět: ${subject}\nFragment: ${msgResponse.data.snippet}`;
                    
                    const geminiResult = await model.generateContent(prompt);
                    const analysisText = geminiResult.response.candidates[0].content.parts[0].text;
                    const analysis = JSON.parse(analysisText.replace(/```json|```/g, ''));

                    if (analysis.category === 'spam' && account.spam_filter) {
                        await gmail.users.messages.modify({ userId: 'me', id: msg.id, requestBody: { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] } });
                        console.log(`CRON: Email "${subject}" pro ${account.email} označen jako SPAM.`);
                    } else if (analysis.category === 'approval_required' && account.approval_required) {
                        await gmail.users.messages.modify({ userId: 'me', id: msg.id, requestBody: { addLabelIds: [approvalLabel.id], removeLabelIds: ['INBOX'] } });
                        console.log(`CRON: Email "${subject}" pro ${account.email} přesunut ke schválení.`);
                    }
                }
            } catch (userError) {
                console.error(`CRON: Chyba při zpracování účtu ${account.email}:`, userError.message);
            }
        }
    } catch (error) {
        console.error('CRON: Došlo k závažné chybě v automatickém workeru:', error);
    } finally {
        if (dbClient) dbClient.release();
        console.log('CRON: Automatická kontrola dokončena.');
    }
});


// =================================================================
// === Spuštění serveru ============================================
// =================================================================

setupDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`✅ Backend server běží na portu ${PORT}`);
        console.log(`🔑 Redirect URI pro Google OAuth: ${REDIRECT_URI}`);
    });
});
