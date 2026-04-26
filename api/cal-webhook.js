// Cal.com webhook receiver. Triggered on BOOKING_CREATED / BOOKING_RESCHEDULED
// / BOOKING_CANCELLED. Verifies HMAC signature, persists to Supabase bookings
// table, updates leads.booking_status + next_session_at, and notifies the
// user + admins via Telegram Bot API.
//
// Required Vercel env vars:
//   CAL_WEBHOOK_SECRET     - matches the secret saved in Cal.com webhook config
//   BOT_TOKEN              - Telegram bot token (already present)
//   ADMIN_IDS              - comma-separated Telegram admin IDs
//   SUPABASE_URL           - Supabase project URL
//   SUPABASE_SERVICE_KEY   - service-role key (NOT anon — needs insert/update on bookings/leads)

import crypto from 'node:crypto';

const TZ = 'Asia/Tashkent';

function verifySignature(rawBody, signatureHeader, secret) {
    if (!signatureHeader || !secret) return false;
    const expected = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
    try {
        return crypto.timingSafeEqual(Buffer.from(signatureHeader, 'hex'), Buffer.from(expected, 'hex'));
    } catch {
        return false;
    }
}

function fmtDateTime(iso) {
    const d = new Date(iso);
    const date = d.toLocaleDateString('ru-RU', { day: '2-digit', month: 'long', timeZone: TZ });
    const time = d.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit', timeZone: TZ });
    return { date, time };
}

async function supabaseRequest(path, opts = {}) {
    const url = `${process.env.SUPABASE_URL}/rest/v1/${path}`;
    const res = await fetch(url, {
        ...opts,
        headers: {
            apikey: process.env.SUPABASE_SERVICE_KEY,
            Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
            'Content-Type': 'application/json',
            Prefer: 'return=representation',
            ...(opts.headers || {}),
        },
    });
    if (!res.ok) {
        const txt = await res.text();
        throw new Error(`Supabase ${res.status}: ${txt}`);
    }
    return res.status === 204 ? null : res.json();
}

async function tgSendMessage(chatId, text) {
    const url = `https://api.telegram.org/bot${process.env.BOT_TOKEN}/sendMessage`;
    const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }),
    });
    return res.ok;
}

async function notifyAdmins(text) {
    const ids = (process.env.ADMIN_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
    await Promise.all(ids.map(id => tgSendMessage(id, text)));
}

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const rawBody = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const signature = req.headers['x-cal-signature-256'];
    if (!verifySignature(rawBody, signature, process.env.CAL_WEBHOOK_SECRET)) {
        return res.status(401).json({ error: 'invalid signature' });
    }

    let body;
    try {
        body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch {
        return res.status(400).json({ error: 'invalid json' });
    }

    const trigger = body.triggerEvent;
    const payload = body.payload || {};
    const meta = payload.metadata || {};
    const telegramId = parseInt(meta.telegram_id || '0', 10);

    if (!telegramId) {
        return res.status(200).json({ ok: true, note: 'no telegram_id in metadata' });
    }

    const calBookingId = String(payload.uid || payload.bookingId || payload.id || '');
    const startTime = payload.startTime || payload.start || null;
    const endTime = payload.endTime || payload.end || null;
    const attendee = (payload.attendees && payload.attendees[0]) || {};
    const rescheduleUrl = payload.rescheduleUrl || payload.rescheduleLink || null;
    const cancelUrl = payload.cancelUrl || payload.cancelLink || null;

    let nextStatus;
    let userMessage;
    let adminLabel;

    if (trigger === 'BOOKING_CREATED') {
        nextStatus = 'scheduled';
        if (startTime) {
            const { date, time } = fmtDateTime(startTime);
            userMessage = `✓ Сессия назначена на <b>${date}</b> в <b>${time}</b> (Tashkent).\n\nЧто дальше:\n• За 24 часа — напоминание\n• За 1 час — ссылка на встречу\n• На сессии — разбор бизнеса и бесплатный аудит` +
                (rescheduleUrl ? `\n\nИзменить время: ${rescheduleUrl}` : '');
        } else {
            userMessage = '✓ Сессия назначена. Подробности придут отдельным письмом.';
        }
        adminLabel = '📅 Новая запись';
    } else if (trigger === 'BOOKING_RESCHEDULED') {
        nextStatus = 'scheduled';
        if (startTime) {
            const { date, time } = fmtDateTime(startTime);
            userMessage = `✓ Сессия перенесена на <b>${date}</b> в <b>${time}</b> (Tashkent).`;
        } else {
            userMessage = '✓ Сессия перенесена. Подробности придут отдельным письмом.';
        }
        adminLabel = '📅 Перенос';
    } else if (trigger === 'BOOKING_CANCELLED') {
        nextStatus = 'cancelled';
        userMessage = 'Сессия отменена. Если планы изменятся — выберите другое время в нашем боте.';
        adminLabel = '📅 Отмена';
    } else {
        return res.status(200).json({ ok: true, note: `unhandled trigger ${trigger}` });
    }

    // Upsert booking row
    await supabaseRequest('bookings', {
        method: 'POST',
        headers: { Prefer: 'resolution=merge-duplicates,return=representation' },
        body: JSON.stringify({
            telegram_id: telegramId,
            cal_booking_id: calBookingId,
            cal_booking_uid: payload.uid || null,
            scheduled_at: startTime,
            ends_at: endTime,
            status: nextStatus,
            attendee_name: attendee.name || null,
            attendee_email: attendee.email || null,
            reschedule_url: rescheduleUrl,
            cancel_url: cancelUrl,
            raw_payload: body,
            updated_at: new Date().toISOString(),
        }),
    });

    // Update lead
    const leadPatch = {
        booking_status: nextStatus,
        next_session_at: nextStatus === 'cancelled' ? null : startTime,
    };
    await supabaseRequest(`leads?telegram_id=eq.${telegramId}`, {
        method: 'PATCH',
        body: JSON.stringify(leadPatch),
    });

    // Notify user + admins
    await tgSendMessage(telegramId, userMessage);
    const adminBody = `<b>${adminLabel}</b>\n${attendee.name || '—'} (@${meta.username || '—'})\n` +
        (startTime ? `${fmtDateTime(startTime).date} ${fmtDateTime(startTime).time}\n` : '') +
        `Lead: /lead ${telegramId}`;
    await notifyAdmins(adminBody);

    return res.status(200).json({ ok: true });
}
