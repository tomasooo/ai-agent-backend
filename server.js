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
const REDIRECT_URI = `https://<nazev-sluzby>.onrender.com/api/oauth/google/callback`; // Doplňte název vaší služby!

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FRONTEND_URL) {
    console.error("Chyba: Chybí potřebné proměnné prostředí!");
    process.exit(1);
}

// Nastavení CORS
const corsOptions = { origin: FRONTEND_URL, optionsSuccessStatus: 200 };
app.use(cors(corsOptions));
app.use(bodyParser.json());

// Klient pro ověření přihlašovacího tokenu
const loginClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Klient pro získání přístupových tokenů pro Gmail API
const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI);

// PŮVODNÍ ENDPOINT PRO PŘIHLÁŠENÍ (zůstává)
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
        console.error("Chyba při ověřování tokenu:", error);
        res.status(401).json({ success: false, message: 'Ověření selhalo.' });
    }
});

// NOVÝ ENDPOINT PRO ZPRACOVÁNÍ SOUHLASU OD GOOGLE
app.get('/api/oauth/google/callback', async (req, res) => {
    try {
        const code = req.query.code;
        if (!code) {
            throw new Error('Autorizační kód chybí.');
        }

        // Výměna kódu za přístupové tokeny
        const { tokens } = await oauth2Client.getToken(code);
        const refresh_token = tokens.refresh_token;

        console.log("ÚSPĚCH! Získán Refresh Token pro práci s Gmailem.");
        
        // DŮLEŽITÉ: ZDE BYSTE BEZPEČNĚ ULOŽILI `refresh_token` DO DATABÁZE
        // Tento token je klíčem k emailu uživatele a musí být šifrovaný a v bezpečí!
        // Spojili byste ho s uživatelem, který je právě přihlášen.
        console.log("Refresh Token (uložit do DB):", refresh_token);

        // Přesměrujeme uživatele zpět na dashboard se zprávou o úspěchu
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=success`);

    } catch (error) {
        console.error("Chyba při zpracování OAuth callbacku:", error.message);
        res.redirect(`${FRONTEND_URL}/dashboard.html?account-linked=error`);
    }
});

app.listen(PORT, () => {
    console.log(`✅ Backend server běží na portu ${PORT}`);
});
