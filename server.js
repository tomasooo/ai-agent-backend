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
    try {
        const code = req.query.code;
        if (!code) {
            throw new Error('Autorizační kód chybí.');
        }

        // 1. Vyměníme kód za tokeny (včetně id_token)
        const { tokens } = await oauth2Client.getToken(code);
        const refresh_token = tokens.refresh_token;

        // 2. Z id_tokenu získáme informace o uživateli (vytvoříme 'ticket')
        const ticket = await loginClient.verifyIdToken({
            idToken: tokens.id_token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const email = payload.email; // Získáme email správným způsobem

        console.log(`ÚSPĚCH! Získán Refresh Token pro ${email}.`);
        if (tokens.refresh_token) {
    console.log(`Získán Refresh Token pro ${email}. Ukládám do databáze.`);
    const client = await pool.connect();
    // Příkaz, který vloží nový záznam, nebo aktualizuje existující
    await client.query(
        'INSERT INTO users (email, refresh_token) VALUES ($1, $2) ON CONFLICT (email) DO UPDATE SET refresh_token = $2',
        [email, tokens.refresh_token]
    );
    client.release();
}
        
        // 3. Přesměrujeme uživatele zpět na dashboard
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=success&new-email=${email}`);

    } catch (error) {
        console.error("Chyba při zpracování OAuth callbacku:", error.message);
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=error`);
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
        const { email, messageId, replyBody } = req.body;
        if (!email || !messageId || !replyBody) {
            return res.status(400).json({ success: false, message: "Chybí potřebné údaje pro odeslání." });
        }

        // 1. Získáme refresh_token z databáze
        const dbClient = await pool.connect();
        const result = await dbClient.query('SELECT refresh_token FROM users WHERE email = $1', [email]);
        dbClient.release();
        const refreshToken = result.rows[0]?.refresh_token;
        if (!refreshToken) return res.status(404).json({ success: false, message: "Token nenalezen." });

        // 2. Načteme detaily původního emailu, abychom mohli správně odpovědět
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: messageId });
        
        const originalHeaders = msgResponse.data.payload.headers;
        const originalSubject = originalHeaders.find(h => h.name.toLowerCase() === 'subject').value;
        const originalFrom = originalHeaders.find(h => h.name.toLowerCase() === 'from').value;
        const originalMessageId = originalHeaders.find(h => h.name.toLowerCase() === 'message-id').value;
        const originalReferences = originalHeaders.find(h => h.name.toLowerCase() === 'references')?.value || '';
        
        // 3. Sestavíme hlavičky pro odpověď
        const replySubject = originalSubject.startsWith('Re: ') ? originalSubject : `Re: ${originalSubject}`;
        const mailParts = [
            `From: ${email}`,
            `To: ${originalFrom}`,
            `Subject: ${replySubject}`,
            `In-Reply-To: ${originalMessageId}`,
            `References: ${originalReferences} ${originalMessageId}`,
            'Content-Type: text/plain; charset=utf-8',
            '',
            replyBody
        ];
        const rawMessage = Buffer.from(mailParts.join('\n')).toString('base64url');

        // 4. Odešleme email
        await gmail.users.messages.send({
            userId: 'me',
            requestBody: {
                raw: rawMessage,
                threadId: msgResponse.data.threadId // Důležité pro zařazení do konverzace
            }
        });

        console.log(`Odpověď na email "${originalSubject}" byla odeslána.`);
        res.json({ success: true, message: "Email byl úspěšně odeslán." });

    } catch (error) {
        console.error("Chyba při odesílání emailu:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se odeslat email." });
    }
});








// UPRAVENÝ ENDPOINT PRO NAČTENÍ EMAILŮ S FILTROVÁNÍM
app.get('/api/gmail/emails', async (req, res) => {
    try {
        const { email, status, period, searchQuery } = req.query; // Získáme i parametry pro filtr
        if (!email) {
            return res.status(400).json({ success: false, message: "Email chybí." });
        }

        const client = await pool.connect();
        const result = await client.query('SELECT refresh_token FROM users WHERE email = $1', [email]);
        client.release();
        
        const refreshToken = result.rows[0]?.refresh_token;
        if (!refreshToken) {
            return res.status(404).json({ success: false, message: "Pro tento email nebyl nalezen token." });
        }

        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    
        const queryParts = [];
        // Filtr podle stavu
        if (status === 'unread') queryParts.push('is:unread');
        if (status === 'spam') queryParts.push('in:spam');
        
        // Filtr podle času
        if (period === 'today') queryParts.push('newer_than:1d');
        if (period === 'week') queryParts.push('newer_than:7d');


        if (searchQuery) {
        queryParts.push(searchQuery);
         }
        
        const finalQuery = queryParts.join(' ');

        const listResponse = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 10,
            q: finalQuery // Použijeme sestavený dotaz
        });

        
        const messageIds = listResponse.data.messages || [];

if (messageIds.length === 0) {
    return res.json({ success: true, emails: [], total: 0 });
}




        
// Pro každou zprávu získáme její detaily
const emailPromises = messageIds.map(async (msg) => {
    const msgResponse = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'metadata', metadataHeaders: ['Subject', 'From', 'Date'] });
    const headers = msgResponse.data.payload.headers;

    const getHeader = (name) => headers.find(h => h.name === name)?.value || '';

    return {
        id: msg.id,
        snippet: msgResponse.data.snippet,
        sender: getHeader('From'),
        subject: getHeader('Subject'),
        date: getHeader('Date')
    };
});

const emails = await Promise.all(emailPromises);
const totalEmails = listResponse.data.resultSizeEstimate;
        
        res.json({ success: true, emails, total: totalEmails });

    } catch (error) {
        console.error("Chyba při načítání emailů:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst emaily." });
    }
});









// === NOVÝ ENDPOINT PRO ANALÝZU EMAILU POMOCÍ GEMINI ===
app.post('/api/gmail/analyze-email', async (req, res) => {
    try {
        const { email, messageId } = req.body;
        if (!email || !messageId) {
            return res.status(400).json({ success: false, message: "Email nebo ID zprávy chybí." });
        }

        // 1. Získáme refresh_token A ZÁROVEŇ NASTAVENÍ z databáze
        const dbClient = await pool.connect();
        const userResult = await dbClient.query('SELECT refresh_token FROM users WHERE email = $1', [email]);
        const settingsResult = await dbClient.query('SELECT * FROM settings WHERE email = $1', [email]);
        dbClient.release();
        
        const refreshToken = userResult.rows[0]?.refresh_token;
        const settings = settingsResult.rows[0];
        if (!refreshToken || !settings) {
            return res.status(404).json({ success: false, message: "Token nebo nastavení nenalezeno." });
        }

        // 2. Načteme plné znění emailu
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        const msgResponse = await gmail.users.messages.get({ userId: 'me', id: messageId });
        
        let emailBody = '';
        if (msgResponse.data.payload.parts) {
            const part = msgResponse.data.payload.parts.find(p => p.mimeType === 'text/plain');
            if (part && part.body.data) {
                emailBody = Buffer.from(part.body.data, 'base64').toString('utf-8');
            }
        } else if (msgResponse.data.payload.body.data) {
            emailBody = Buffer.from(msgResponse.data.payload.body.data, 'base64').toString('utf-8');
        }

        // 3. Vytvoříme PROMPT S VYUŽITÍM NASTAVENÍ
        const prompt = `Jsi profesionální emailový asistent. Analyzuj následující email. V odpovědi uveď pouze JSON objekt se třemi klíči: "summary" (stručné shrnutí emailu v jedné větě), "sentiment" (pozitivní, negativní, nebo neutrální) a "suggested_reply" (návrh krátké, profesionální odpovědi v češtině).
        Uživatel si přeje, aby odpověď byla v tomto stylu:
        - Tón: ${settings.tone}
        - Délka: ${settings.length}
        Na konec navrhované odpovědi přidej tento podpis, pokud je uveden: "${settings.signature}"
        
        Email k analýze:
        ---
        ${emailBody.substring(0, 3000)}`;

        // 4. Zeptáme se Gemini a pošleme odpověď
        const geminiResult = await model.generateContent(prompt);
        const analysisText = geminiResult.response.candidates[0].content.parts[0].text;
        const cleanedText = analysisText.replace(/```json|```/g, '');
        res.json({ success: true, analysis: JSON.parse(cleanedText) });

    } catch (error) {
        console.error("Chyba při analýze emailu:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se analyzovat email." });
    }
});






// Endpoint pro načtení nastavení
app.get('/api/settings', async (req, res) => {
    let client;
    try {
        const { email } = req.query;
        client = await pool.connect();
        let result = await client.query('SELECT * FROM settings WHERE email = $1', [email]);
        
        if (result.rows.length === 0) {
            await client.query('INSERT INTO settings (email) VALUES ($1)', [email]);
            result = await client.query('SELECT * FROM settings WHERE email = $1', [email]);
        }
        
        res.json({ success: true, settings: result.rows[0] });
    } catch (error) {
        console.error("Chyba při načítání nastavení:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst nastavení." });
    } finally {
        if (client) {
            client.release();
        }
    }
});






// Endpoint pro uložení nastavení
app.post('/api/settings', async (req, res) => {
    let client;
    try {
        const { email, tone, length, signature, auto_reply, approval_required, spam_filter } = req.body;
        client = await pool.connect();
        await client.query(
            `UPDATE settings SET tone = $1, length = $2, signature = $3, auto_reply = $4, approval_required = $5, spam_filter = $6
             WHERE email = $7`,
            [tone, length, signature, auto_reply, approval_required, spam_filter, email]
        );
        res.json({ success: true, message: "Nastavení bylo úspěšně uloženo." });
    } catch (error) {
        console.error("Chyba při ukládání nastavení:", error);
        res.status(500).json({ success: false, message: "Nepodařilo se uložit nastavení." });
    } finally {
        if (client) {
            client.release();
        }
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

