// server.js
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg'); // Ovladač pro PostgreSQL
const { google } = require('googleapis'); // PŘIDÁNO: Knihovna pro Google API


const app = express();
const PORT = process.env.PORT || 3000;

// Načtení proměnných prostředí
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;
const DATABASE_URL = process.env.DATABASE_URL;
console.log("DEBUG: Načtená DATABASE_URL je:", DATABASE_URL);
const SERVER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${SERVER_URL}/api/oauth/google/callback`;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FRONTEND_URL || !DATABASE_URL) {
    console.error("Chyba: Chybí jedna z klíčových proměnných prostředí!");
    process.exit(1);
}

// Nastavení databázového spojení
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false } // Nutné pro Render
});

// Funkce pro vytvoření tabulky, pokud neexistuje
async function setupDatabase() {
    try {
        const client = await pool.connect();
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                email VARCHAR(255) PRIMARY KEY,
                refresh_token TEXT NOT NULL,
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `);
        client.release();
        console.log("Tabulka 'users' je připravena.");
    } catch (err) {
        console.error('Chyba při nastavování databáze:', err);
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
    try {
        const { token } = req.body;
        const ticket = await loginClient.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        console.log(`Uživatel přihlášen: ${payload.name} (${payload.email})`);
        res.status(200).json({ success: true, user: payload });
    } catch (error) {
        console.error("Chyba při ověřování přihlašovacího tokenu:", error);
        res.status(401).json({ success: false, message: 'Ověření selhalo.' });
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

    try {
    const { email } = req.body;
    const client = await pool.connect();
    
    // 1. Najdeme refresh_token v databázi
    const result = await client.query('SELECT refresh_token FROM users WHERE email = $1', [email]);
    const refreshToken = result.rows[0]?.refresh_token;

    if (refreshToken) {
        // 2. Řekneme Googlu, aby zneplatnil token
        await oauth2Client.revokeToken(refreshToken);
        console.log(`Token pro ${email} byl úspěšně zneplatněn u Googlu.`);
        
        // 3. Smažeme záznam z naší databáze
        await client.query('DELETE FROM users WHERE email = $1', [email]);
        console.log(`Záznam pro ${email} byl smazán z databáze.`);
    }
    client.release();
    res.status(200).json({ success: true, message: "Účet byl úspěšně odpojen." });

} catch (error) {
    console.error("Chyba při zneplatnění tokenu:", error.message);
    res.status(500).json({ success: false, message: "Nepodařilo se odpojit účet." });
}
});

// === NOVÝ ENDPOINT PRO NAČTENÍ EMAILŮ ===
app.get('/api/gmail/emails', async (req, res) => {
    try {
        const { email } = req.query; // Získáme email z požadavku
        if (!email) {
            return res.status(400).json({ success: false, message: "Email chybí." });
        }

        // 1. Získáme refresh_token z databáze
        const client = await pool.connect();
        const result = await client.query('SELECT refresh_token FROM users WHERE email = $1', [email]);
        client.release();
        
        const refreshToken = result.rows[0]?.refresh_token;
        if (!refreshToken) {
            return res.status(404).json({ success: false, message: "Pro tento email nebyl nalezen token. Propojte prosím účet." });
        }

        // 2. Nastavíme token do OAuth klienta a vytvoříme Gmail klienta
        oauth2Client.setCredentials({ refresh_token: refreshToken });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        // 3. Získáme seznam posledních 10 zpráv (jen jejich ID)
        const listResponse = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 10,
        });
        const messageIds = listResponse.data.messages || [];
        
        if (messageIds.length === 0) {
            return res.json({ success: true, emails: [], total: 0 });
        }

        // 4. Pro každou zprávu získáme její detaily
        const emailPromises = messageIds.map(async (msg) => {
            const msgResponse = await gmail.users.messages.get({ userId: 'me', id: msg.id, format: 'metadata', metadataHeaders: ['Subject', 'From', 'Date'] });
            const headers = msgResponse.data.payload.headers;
            
            // Pomocná funkce pro nalezení hodnoty v hlavičkách
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
        const totalEmails = listResponse.data.resultSizeEstimate; // Celkový počet emailů v inboxu

        res.json({ success: true, emails, total: totalEmails });

    } catch (error) {
        console.error("Chyba při načítání emailů:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se načíst emaily." });
    }
});


app.listen(PORT, () => {
    console.log(`✅ Backend server běží na portu ${PORT}`);
    setupDatabase(); // Zavoláme nastavení databáze při startu
});
