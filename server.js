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
const REDIRECT_URI = `https://ai-email-server-stejdesign.onrender.com/api/oauth/google/callback`;

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !FRONTEND_URL) {
    console.error("Chyba: Chybí potřebné proměnné prostředí!");
    process.exit(1);
}

// Nastavení CORS
const corsOptions = { origin: FRONTEND_URL, optionsSuccessStatus: 200 };
app.use(cors(corsOptions));
app.use(bodyParser.json());

const loginClient = new OAuth2Client(GOOGLE_CLIENT_ID);
const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI);

// ENDPOINT PRO PŘIHLÁŠENÍ
app.post('/api/auth/google', async (req, res) => {
    // ... kód pro přihlášení zůstává beze změny ...
});

// ENDPOINT PRO ZPRACOVÁNÍ SOUHLASU OD GOOGLE
app.get('/api/oauth/google/callback', async (req, res) => {
    // ... kód pro callback zůstává beze změny ...
});


// === NOVÝ ENDPOINT PRO ODPOJENÍ ÚČTU (REVOKE TOKEN) ===
app.post('/api/oauth/google/revoke', async (req, res) => {
    try {
        const { email } = req.body; // Email, který chceme odpojit

        // DŮLEŽITÉ: V reálné aplikaci byste udělali toto:
        // 1. Našli byste uživatele v databázi podle jeho session.
        // 2. Našli byste jeho uložený `refresh_token` pro daný email.
        const refreshToken = "ZDE_BY_BYL_REFRESH_TOKEN_Z_DATABÁZE"; // Toto je jen placeholder!
        
        if (refreshToken) {
            // Řekneme Googlu, aby zneplatnil tento token
            await oauth2Client.revokeToken(refreshToken);
            console.log(`Token pro email ${email} byl úspěšně zneplatněn.`);
        }

        // 3. Smazali byste refresh_token z vaší databáze.
        console.log(`Placeholder: Token pro ${email} by byl smazán z databáze.`);

        res.status(200).json({ success: true, message: "Účet byl úspěšně odpojen." });

    } catch (error) {
        console.error("Chyba při zneplatnění tokenu:", error.message);
        res.status(500).json({ success: false, message: "Nepodařilo se zneplatnit oprávnění." });
    }
});


app.listen(PORT, () => {
    console.log(`✅ Backend server běží na portu ${PORT}`);
});
