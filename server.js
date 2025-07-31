// server.js
const express = require('express');
const { OAuth2Client } = require('google-auth-library');
const bodyParser = require('body-parser');
const cors = require('cors'); // Importujeme CORS

const app = express();
const PORT = 3000; // Port, na kterém poběží náš backend

// ❗ DŮLEŽITÉ: Nahraďte svým Client ID z Google Cloud Console
const GOOGLE_CLIENT_ID = "990614891314-kugic255rq68tt1m7uqg4rdp9jdig5lb.apps.googleusercontent.com"; 
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Nastavení CORS, aby server přijímal požadavky z vašeho frontendu
const corsOptions = {
    origin: 'http://127.0.0.1:5500', // Povolíme pouze vaši frontend adresu
    optionsSuccessStatus: 200 
};
app.use(cors(corsOptions)); // Použijeme CORS
app.use(bodyParser.json());

// Endpoint pro ověření Google tokenu
app.post('/api/auth/google', async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) {
            return res.status(400).json({ success: false, message: 'Token chybí.' });
        }

        // Bezpečné ověření tokenu na straně serveru
        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: GOOGLE_CLIENT_ID,
        });

        const payload = ticket.getPayload();
        const { name, email, picture } = payload;

        console.log(`Uživatel úspěšně ověřen: ${name} (${email})`);

        // V reálné aplikaci byste zde uživatele uložili do databáze
        // a vytvořili mu session pro přihlášení.

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

app.listen(PORT, () => {
    console.log(`✅ Backend server běží na http://localhost:${PORT}`);
    console.log('Očekávám požadavky z http://127.0.0.1:5500');
});