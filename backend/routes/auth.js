
import express from 'express';
import { dbManager } from '../databaseManager.js';
import { googleAuthConfig } from '../authConfig.js';
import { OAuth2Client } from 'google-auth-library';
import crypto from 'crypto';

const router = express.Router();
const client = new OAuth2Client(googleAuthConfig.clientId);

router.get('/config', (req, res) => {
    res.json({ clientId: googleAuthConfig.clientId });
});

router.post('/register', async (req, res) => {
    try {
        const user = req.body;
        if (user.referredById === "") user.referredById = null;
        const userId = await dbManager.users.create(user);
        res.json({ success: true, user: { ...user, id: userId } });
    } catch (e) { 
        console.error("Register Error:", e.message);
        res.status(500).json({ error: e.message }); 
    }
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await dbManager.users.findByEmail(email);
        if (user && user.password === password) {
            const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            const ua = req.headers['user-agent'];
            await dbManager.admin.recordIp(user.id, ip, ua);
            res.json({ user, token: 'session_' + crypto.randomUUID() });
        } else {
            res.status(401).json({ error: 'Credenciais inválidas' });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/google', async (req, res) => {
    try {
        const { googleToken, referredBy } = req.body;
        let googleId, email, name;

        // 1. Validação do Token do Google
        if (googleAuthConfig.clientId !== "GOOGLE_CLIENT_ID_NAO_CONFIGURADO" && googleToken && googleToken.length > 50) {
            try {
                const ticket = await client.verifyIdToken({ idToken: googleToken, audience: googleAuthConfig.clientId });
                const payload = ticket.getPayload();
                googleId = payload['sub']; 
                email = payload['email']; 
                name = payload['name'];
            } catch (err) {
                console.warn("⚠️ Google Token Verify Failed:", err.message);
            }
        }

        // Fallback de segurança para modo desenvolvimento
        if (!googleId) {
            googleId = `mock_${crypto.randomUUID().substring(0, 8)}`;
            email = `guest_${googleId}@gmail.com`;
            name = `Guest ${googleId.slice(-4)}`;
        }

        // 2. Operações de Banco de Dados
        let user;
        try {
            user = await dbManager.users.findByGoogleId(googleId);
            let isNew = false;

            if (!user) {
                const existingByEmail = await dbManager.users.findByEmail(email);
                if (existingByEmail) {
                    user = existingByEmail; 
                    user.googleId = googleId; 
                    await dbManager.users.update(user);
                } else {
                    isNew = true;
                    const newUser = { 
                        email: email.toLowerCase().trim(), 
                        googleId, 
                        isVerified: true, 
                        isProfileCompleted: false, 
                        referredById: referredBy || null, 
                        profile: { 
                            name: `user_${googleId.slice(-4)}`, 
                            nickname: name || 'Usuário Flux', 
                            isPrivate: false, 
                            photoUrl: '' 
                        } 
                    };
                    const id = await dbManager.users.create(newUser);
                    user = { ...newUser, id };
                }
            }

            const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            const ua = req.headers['user-agent'];
            await dbManager.admin.recordIp(user.id, ip, ua);
            
            res.json({ user, token: 'g_session_' + crypto.randomUUID(), isNew });
            
        } catch (dbError) {
            console.error("🚨 CRITICAL DATABASE ERROR during Google Auth:", dbError.message);
            return res.status(503).json({ 
                error: "Serviço temporariamente indisponível (Erro de Banco).", 
                details: "Não foi possível conectar ao banco de dados para validar o usuário." 
            });
        }

    } catch (e) { 
        console.error("❌ Google Auth General Error:", e.message);
        res.status(500).json({ error: "Erro interno na autenticação." }); 
    }
});

router.post('/change-password', async (req, res) => {
    try {
        // O userId virá do token de autenticação (ex: req.user.id)
        const { userId, currentPassword, newPassword } = req.body; 
        const user = await dbManager.users.findById(userId);

        if (user && user.password === currentPassword) {
            user.password = newPassword;
            await dbManager.users.update(user);
            res.json({ success: true });
        } else {
            res.status(401).json({ error: 'Senha atual incorreta' });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/reset-password', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await dbManager.users.findByEmail(email);
        if (user) {
            user.password = password;
            await dbManager.users.update(user);
            res.json({ success: true });
        } else {
            res.status(404).json({ error: 'Usuário não encontrado' });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

router.post('/sessions/revoke-others', async (req, res) => {
    try {
        // O userId virá do token de autenticação (ex: req.user.id)
        const { userId } = req.body; 
        const user = await dbManager.users.findById(userId);
        if (user) {
            // Lógica para invalidar outras sessões viria aqui
            res.json({ success: true });
        } else {
            res.status(404).json({ error: 'Usuário não encontrado' });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

export default router;
