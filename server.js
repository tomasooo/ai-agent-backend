// server.js
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();

// 1. Port se načte z proměnných prostředí Renderu (nebo použije 3000 pro lokální vývoj)
const PORT = process.env.PORT || 3000;

// 2. Client ID se bezpečně načte z proměnných prostředí
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
if (!GOOGLE_CLIENT_ID) {
    console.error("Chyba: GOOGLE_CLIENT_ID není nastaveno v proměnných prostředí!");
    process.exit(1);
}
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// 3. Adresa frontendu se načte z proměnných prostředí
const FRONTEND_URL = process.env.FRONTEND_URL;
if (!FRONTEND_URL) {
    console.error("Chyba: FRONTEND_URL není nastaveno v proměnných prostředí!");
    process.exit(1);
}
const corsOptions = {
    origin: FRONTEND_URL,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
app.use(bodyParser.json());

// Endpoint pro ověření Google tokenu (zůstává stejný)
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(400).json({ success: false, message: 'Token chybí.' });
        }

        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { name, email, picture } = payload;

        console.log(`Uživatel úspěšně ověřen: ${name} (${email})`);

        // Zde by v budoucnu přišla práce s databází

        res.status(200).json({
            success: true,
            message: "Přihlášení úspěšné.",
            user: { name, email, picture },
        });

    } catch (error) {
        console.error("Chyba při ověřování tokenu:", error);
        res.status(401).json({ success: false, message: 'Ověření selhalo. Neplatný token.' });
    }
});

// === NOVÝ ENDPOINT PRO ODPOJENÍ ÚČTU (REVOKE TOKEN) ===
app.post('/api/oauth/google/revoke', async (req, res) => {
    try {
        const { email } = req.body; // Email, který chceme odpojit

        // DŮLEŽITÉ: V reálné aplikaci byste udělali toto:
        // 1. Našli byste uživatele v databázi podle jeho session.
        // 2. Našli byste jeho uložený `refresh_token` pro daný email.
        const refreshToken = "ZDE_BY_BYL_REFRESH_TOKEN_Z_DATABÁZE"; // Toto je jen placeholder!
        
        if (refreshToken && refreshToken !== "ZDE_BY_BYL_REFRESH_TOKEN_Z_DATABÁZE") {
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
    console.log(`Očekávám požadavky z: ${FRONTEND_URL}`);
});
