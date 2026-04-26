// Server-side proxy for Telegram Bot API calls made from the admin Mini App.
// Keeps BOT_TOKEN out of the browser. Verifies the caller is an admin via
// Telegram initData HMAC + ADMIN_IDS allowlist.
//
// Env vars required on the Vercel project:
//   BOT_TOKEN  - Telegram bot token (server-side only)
//   ADMIN_IDS  - comma-separated Telegram admin user IDs
//
// Request body (JSON):
//   {
//     initData:  string,                                // window.Telegram.WebApp.initData
//     action:    "sendMessage" | "sendPhoto" | "sendVideo" | "sendDocument",
//     chat_id:   number,
//     text?:     string,                                // for sendMessage / file caption
//     parse_mode?: string,                              // e.g. "HTML"
//     file?:     { name: string, mimeType: string, data: string /* base64 */ }
//   }

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

async function tgJson(botToken, method, body) {
    const res = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => ({}));
    return { ok: res.ok && json.ok, status: res.status, json };
}

async function tgMultipart(botToken, method, fields, fileField, fileName, fileMime, fileBuf) {
    const form = new FormData();
    for (const [k, v] of Object.entries(fields)) {
        if (v != null) form.append(k, String(v));
    }
    const blob = new Blob([fileBuf], { type: fileMime || 'application/octet-stream' });
    form.append(fileField, blob, fileName);
    const res = await fetch(`https://api.telegram.org/bot${botToken}/${method}`, {
        method: 'POST',
        body: form,
    });
    const json = await res.json().catch(() => ({}));
    return { ok: res.ok && json.ok, status: res.status, json };
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

    const { initData, action, chat_id, text, parse_mode, file } = req.body || {};
    if (typeof initData !== 'string' || typeof action !== 'string' || (chat_id == null)) {
        res.status(400).json({ error: 'bad_payload' });
        return;
    }

    const user = verifyInitData(initData, BOT_TOKEN);
    if (!user || !user.id) {
        res.status(401).json({ error: 'invalid_init_data' });
        return;
    }

    const adminIds = ADMIN_IDS.split(',').map((s) => Number(s.trim())).filter(Boolean);
    if (!adminIds.includes(user.id)) {
        res.status(403).json({ error: 'not_admin' });
        return;
    }

    try {
        if (action === 'sendMessage') {
            if (typeof text !== 'string' || !text.trim()) {
                res.status(400).json({ error: 'empty_text' });
                return;
            }
            const body = { chat_id, text };
            if (parse_mode) body.parse_mode = parse_mode;
            const r = await tgJson(BOT_TOKEN, 'sendMessage', body);
            if (!r.ok) {
                res.status(502).json({ error: 'tg_failed', detail: r.json.description || null });
                return;
            }
            res.status(200).json({ ok: true });
            return;
        }

        if (action === 'sendPhoto' || action === 'sendVideo' || action === 'sendDocument') {
            if (!file || typeof file.data !== 'string' || !file.name) {
                res.status(400).json({ error: 'missing_file' });
                return;
            }
            const fieldByAction = {
                sendPhoto: 'photo',
                sendVideo: 'video',
                sendDocument: 'document',
            };
            const fileField = fieldByAction[action];
            const buf = Buffer.from(file.data, 'base64');
            const fields = { chat_id };
            if (text) fields.caption = text;
            if (parse_mode) fields.parse_mode = parse_mode;
            const r = await tgMultipart(BOT_TOKEN, action, fields, fileField, file.name, file.mimeType, buf);
            if (!r.ok) {
                res.status(502).json({ error: 'tg_failed', detail: r.json.description || null });
                return;
            }
            res.status(200).json({ ok: true });
            return;
        }

        res.status(400).json({ error: 'unknown_action' });
    } catch (e) {
        console.error('admin-tg', e);
        res.status(500).json({ error: 'internal', detail: String(e.message || e) });
    }
}
