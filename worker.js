// worker.js
const { OAuth2Client } = require('google-auth-library');
const { google } = require('googleapis');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { Pool } = require('pg');

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, DATABASE_URL, GEMINI_API_KEY, RENDER_EXTERNAL_URL } = process.env;
const REDIRECT_URI = `${RENDER_EXTERNAL_URL}/api/oauth/google/callback`;

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
const oauth2Client = new OAuth2Client(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, REDIRECT_URI);
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash"});

async function processEmails() {
    console.log('Spouštím automatickou kontrolu emailů...');
    const dbClient = await pool.connect();
    try {
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
                const analysis = JSON.parse(geminiResult.response.text().replace(/```json|```/g, ''));

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
        dbClient.release();
        pool.end();
    }
    console.log('Automatická kontrola dokončena.');
}

processEmails();
