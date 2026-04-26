// Vercel serverless function: forwards a live-chat message from the TWA
// straight to admins via the Telegram Bot API. Bypasses the sendData()
// launch-context restriction — works from any TWA entry point.
//
// Security: verifies Telegram initData HMAC so only real Mini App users of
// this bot can post. Env vars required on the Vercel project:
//   BOT_TOKEN       - Telegram bot token
//   ADMIN_IDS       - comma-separated Telegram admin IDs
//   SUPABASE_URL    - Supabase project URL
//   SUPABASE_KEY    - Supabase anon/service key with insert on leads/events/conversations

import crypto from 'node:crypto';

function verifyInitData(initData, botToken) {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    params.delete('hash');
    const dataCheckString = [...params.entries()]
        .map(([k, v]) => `${k}=${v}`)
        .sort()
        .join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
    const computed = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    if (computed !== hash) return null;
    try {
        return JSON.parse(params.get('user') || 'null');
    } catch {
        return null;
    }
}

async function tgSend(botToken, chatId, text, replyMarkup) {
    const body = { chat_id: chatId, text, parse_mode: 'HTML' };
    if (replyMarkup) body.reply_markup = replyMarkup;
    const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return res.ok;
}

async function supabaseRequest(path, method, body) {
    const { SUPABASE_URL, SUPABASE_KEY } = process.env;
    if (!SUPABASE_URL || !SUPABASE_KEY) return null;
    const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
        method,
        headers: {
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
            'Content-Type': 'application/json',
            'Prefer': 'return=minimal',
        },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
        console.error('supabase', path, res.status, await res.text());
    }
    return res.ok;
}

export default async function handler(req, res) {
    if (req.method !== 'POST') {
        res.status(405).json({ error: 'method_not_allowed' });
        return;
    }
    const { BOT_TOKEN, ADMIN_IDS } = process.env;
    if (!BOT_TOKEN || !ADMIN_IDS) {
        res.status(500).json({ error: 'server_not_configured' });
        return;
    }

    const { initData, message } = req.body || {};
    if (typeof initData !== 'string' || typeof message !== 'string') {
        res.status(400).json({ error: 'bad_payload' });
        return;
    }
    const msg = message.trim();
    if (!msg) {
        res.status(400).json({ error: 'empty_message' });
        return;
    }
    if (msg.length > 2000) {
        res.status(400).json({ error: 'message_too_long' });
        return;
    }

    const user = verifyInitData(initData, BOT_TOKEN);
    if (!user || !user.id) {
        res.status(401).json({ error: 'invalid_init_data' });
        return;
    }

    const telegramId = user.id;
    const name = [user.first_name, user.last_name].filter(Boolean).join(' ') || '—';
    const username = user.username ? `@${user.username}` : '—';
    const escape = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const adminText =
        `💬 <b>Жив-чат запрос (TWA)</b>\n\n` +
        `👤 ${escape(name)} (${escape(username)})\n` +
        `🆔 <code>${telegramId}</code>\n\n` +
        `📝 ${escape(msg)}`;

    // Persist to Supabase (best-effort; do not fail the request on error)
    await Promise.all([
        supabaseRequest(`leads?telegram_id=eq.${telegramId}`, 'PATCH', { live_chat: true }),
        supabaseRequest('conversations', 'POST', {
            telegram_id: telegramId,
            role: 'user',
            content: msg,
            source: 'live_chat',
        }),
        supabaseRequest('events', 'POST', {
            telegram_id: telegramId,
            event_type: 'live_chat_requested',
            event_data: { source: 'twa_direct' },
        }),
    ]).catch((e) => console.error('persist', e));

    // Attach the same "Reply" callback button the bot's _notify_managers uses,
    // so the existing bot-side reply flow (cb_live_reply → handle_admin_reply
    // in bot/handlers/live_chat.py) picks up from here.
    const replyMarkup = {
        inline_keyboard: [[{ text: '💬 Reply', callback_data: `lr:${telegramId}` }]],
    };

    const adminIds = ADMIN_IDS.split(',').map((s) => s.trim()).filter(Boolean);
    const results = await Promise.allSettled(
        adminIds.map((id) => tgSend(BOT_TOKEN, id, adminText, replyMarkup))
    );
    const delivered = results.filter((r) => r.status === 'fulfilled' && r.value).length;

    if (delivered === 0) {
        res.status(502).json({ error: 'notify_failed' });
        return;
    }
    res.status(200).json({ ok: true, delivered });
}
