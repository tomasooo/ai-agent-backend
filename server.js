// server.js
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Načtení proměnných prostředí
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FRONTEND_URL = process.env.FRONTEND_URL;
const SERVER_URL = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;
const REDIRECT_URI = `${SERVER_URL}/api/oauth/google/callback`;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FRONTEND_URL) {
    console.error("Chyba: Chybí potřebné proměnné prostředí (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, FRONTEND_URL)!");
    process.exit(1);
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
        if (refresh_token) {
            console.log("Refresh Token (uložit do DB):", refresh_token);
             // ZDE BYSTE BEZPEČNĚ ULOŽILI `refresh_token` DO DATABÁZE
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
        const refreshToken = "ZDE_BY_BYL_REFRESH_TOKEN_Z_DATABÁZE";
        
        if (refreshToken && refreshToken !== "ZDE_BY_BYL_REFRESH_TOKEN_Z_DATABÁZE") {
            await oauth2Client.revokeToken(refreshToken);
            console.log(`Token pro email ${email} byl úspěšně zneplatněn.`);
        }

        console.log(`Placeholder: Token pro ${email} by byl smazán z databáze.`);
        res.status(200).json({ success: true, message: "Účet byl úspěšně odpojen." });

    } catch (error) {
        console.error("Chyba při zneplatnění tokenu:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se zneplatnit oprávnění." });
    }
});

app.listen(PORT, () => {
    console.log(`✅ Backend server běží na portu ${PORT}`);
    console.log(`Očekávám požadavky z: ${FRONTEND_URL}`);
});
