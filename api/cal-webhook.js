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

function fmtDateTime(iso, lang = 'ru') {
    const d = new Date(iso);
    const locale = lang === 'uz' ? 'ru-RU' : 'ru-RU';
    const date = d.toLocaleDateString(locale, { day: '2-digit', month: 'long', timeZone: TZ });
    const time = d.toLocaleTimeString(locale, { hour: '2-digit', minute: '2-digit', timeZone: TZ });
    return { date, time };
}

async function fetchLeadLang(telegramId) {
    try {
        const url = `${process.env.SUPABASE_URL}/rest/v1/leads?telegram_id=eq.${telegramId}&select=preferred_lang`;
        const res = await fetch(url, {
            headers: {
                apikey: process.env.SUPABASE_SERVICE_KEY,
                Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
            },
        });
        if (!res.ok) return 'ru';
        const rows = await res.json();
        return (rows[0] && rows[0].preferred_lang) || 'ru';
    } catch {
        return 'ru';
    }
}

function buildUserMessage(trigger, startTime, lang, rescheduleUrl, attendee) {
    const ru = lang === 'ru';
    if (trigger === 'BOOKING_CREATED' || trigger === 'BOOKING_RESCHEDULED') {
        if (!startTime) {
            return ru
                ? '✓ Сессия назначена. Подробности придут отдельным письмом.'
                : '✓ Sessiya tayinlandi. Tafsilotlar alohida xabar bilan yuboriladi.';
        }
        const { date, time } = fmtDateTime(startTime, lang);
        const verbRu = trigger === 'BOOKING_CREATED' ? 'назначена' : 'перенесена';
        const verbUz = trigger === 'BOOKING_CREATED' ? 'tayinlandi' : 'ko‘chirildi';
        const lines = ru
            ? [
                `✓ Стратегическая сессия ${verbRu}`,
                ``,
                `📅 <b>${date}</b> в <b>${time}</b> (Tashkent)`,
                attendee && attendee.email ? `📧 ${attendee.email}` : null,
                ``,
                `За 2 часа до встречи мы пришлём напоминание с возможностью подтвердить, отменить или перенести.`,
            ]
            : [
                `✓ Strategik sessiya ${verbUz}`,
                ``,
                `📅 <b>${date}</b> soat <b>${time}</b> da (Toshkent)`,
                attendee && attendee.email ? `📧 ${attendee.email}` : null,
                ``,
                `Uchrashuvdan 2 soat oldin biz eslatma yuboramiz — tasdiqlash, bekor qilish yoki ko‘chirish imkoniyati bilan.`,
            ];
        if (rescheduleUrl) {
            lines.push('');
            lines.push(ru ? `Изменить время: ${rescheduleUrl}` : `Vaqtni o‘zgartirish: ${rescheduleUrl}`);
        }
        return lines.filter((l) => l !== null).join('\n');
    }
    if (trigger === 'BOOKING_CANCELLED') {
        return ru
            ? 'Сессия отменена. Если планы изменятся — выберите другое время в нашем боте.'
            : 'Sessiya bekor qilindi. Rejalar o‘zgarsa — botimizda boshqa vaqt tanlang.';
    }
    return '';
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
    let telegramId = parseInt(meta.telegram_id || '0', 10);

    // Fallback chain when Cal.com strips metadata (embed serialization bug):
    //   1. attendee SMS email of the form <phone>@sms.cal.com → leads.phone
    //   2. attendee real email → leads.email
    //   3. responses.smsReminderNumber / phone field → leads.phone
    if (!telegramId) {
        const attendee = (payload.attendees && payload.attendees[0]) || {};
        const attendeeEmail = attendee.email || null;
        const responses = payload.responses || {};

        const candidates = [];
        if (attendeeEmail && attendeeEmail.endsWith('@sms.cal.com')) {
            const phone = attendeeEmail.replace(/@sms\.cal\.com$/, '').replace(/^\+/, '');
            if (phone) candidates.push({ field: 'phone', value: phone });
        } else if (attendeeEmail) {
            candidates.push({ field: 'email', value: attendeeEmail });
        }
        const respPhone = responses.smsReminderNumber || responses.phone || responses.attendeePhoneNumber;
        if (respPhone) {
            const cleaned = String(respPhone).replace(/^\+/, '').replace(/\s+/g, '');
            if (cleaned) candidates.push({ field: 'phone', value: cleaned });
        }

        for (const c of candidates) {
            try {
                const url = `${process.env.SUPABASE_URL}/rest/v1/leads?${c.field}=eq.${encodeURIComponent(c.value)}&select=telegram_id&limit=1`;
                const r = await fetch(url, {
                    headers: {
                        apikey: process.env.SUPABASE_SERVICE_KEY,
                        Authorization: `Bearer ${process.env.SUPABASE_SERVICE_KEY}`,
                    },
                });
                if (r.ok) {
                    const rows = await r.json();
                    if (rows[0] && rows[0].telegram_id) {
                        telegramId = parseInt(rows[0].telegram_id, 10);
                        console.log(`webhook: resolved telegram_id ${telegramId} via ${c.field}=${c.value}`);
                        break;
                    }
                }
            } catch (e) {
                console.error(`lead-${c.field} lookup failed`, e);
            }
        }
    }

    if (!telegramId) {
        console.warn('webhook: no telegram_id', {
            trigger,
            metadataKeys: Object.keys(meta),
            metadata: meta,
            attendeeEmail: payload.attendees && payload.attendees[0] && payload.attendees[0].email,
            payloadKeys: Object.keys(payload),
        });
        return res.status(200).json({ ok: true, note: 'no telegram_id in metadata or by email' });
    }

    const calBookingId = String(payload.uid || payload.bookingId || payload.id || '');
    const startTime = payload.startTime || payload.start || null;
    const endTime = payload.endTime || payload.end || null;
    const attendee = (payload.attendees && payload.attendees[0]) || {};
    const rescheduleUrl = payload.rescheduleUrl || payload.rescheduleLink || null;
    const cancelUrl = payload.cancelUrl || payload.cancelLink || null;

    let nextStatus;
    let adminLabel;
    if (trigger === 'BOOKING_CREATED') {
        nextStatus = 'scheduled';
        adminLabel = '📅 Новая запись';
    } else if (trigger === 'BOOKING_RESCHEDULED') {
        nextStatus = 'scheduled';
        adminLabel = '📅 Перенос';
    } else if (trigger === 'BOOKING_CANCELLED') {
        nextStatus = 'cancelled';
        adminLabel = '📅 Отмена';
    } else {
        return res.status(200).json({ ok: true, note: `unhandled trigger ${trigger}` });
    }

    const lang = await fetchLeadLang(telegramId);
    const userMessage = buildUserMessage(trigger, startTime, lang, rescheduleUrl, attendee);

    // Upsert booking row. On RESCHEDULED we clear reminder_sent_at/confirmed_at
    // so the new slot gets its own 2h reminder. On CANCELLED we clear them too.
    const bookingRow = {
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
    };
    if (trigger === 'BOOKING_RESCHEDULED' || trigger === 'BOOKING_CANCELLED') {
        bookingRow.reminder_sent_at = null;
        bookingRow.confirmed_at = null;
    }
    await supabaseRequest('bookings?on_conflict=cal_booking_id', {
        method: 'POST',
        headers: { Prefer: 'resolution=merge-duplicates,return=representation' },
        body: JSON.stringify(bookingRow),
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
