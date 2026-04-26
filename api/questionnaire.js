// Vercel serverless function: persists TWA questionnaire completion to
// Supabase and notifies admins via the Bot API. Mirrors the logic in
// bot/handlers/twa.py (questionnaire_complete branch) so the TWA can
// finalize without calling Telegram.WebApp.sendData() (which closes the
// WebApp). After this returns ok, the TWA switches to the main app view.
//
// Env vars required on the Vercel project:
//   BOT_TOKEN     - Telegram bot token
//   ADMIN_IDS     - comma-separated Telegram admin IDs
//   SUPABASE_URL  - Supabase project URL
//   SUPABASE_KEY  - Supabase anon/service key (insert/update on leads/events)

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

async function tgSend(botToken, chatId, text) {
    const res = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'HTML' }),
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
            'Prefer': method === 'GET' ? 'count=exact' : 'return=representation',
        },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) {
        console.error('supabase', path, res.status, await res.text());
        return null;
    }
    if (method === 'GET' || (method === 'PATCH' && body)) {
        try { return await res.json(); } catch { return null; }
    }
    return true;
}

// ── Value normalization (mirror of bot/handlers/twa.py) ──────────
const VERTICAL_LEGACY = {
    realestate: 'q_v_realestate',
    health: 'q_v_clinic',
    education: 'q_v_education',
    consulting: 'q_v_education',
};
const SPEND_LEGACY = {
    '1000_1500': 'q_spend_1k_3k',
    '2000_3000': 'q_spend_1k_3k',
    '3000_5000': 'q_spend_3k_10k',
    '5000_plus': 'q_spend_10k_plus',
};
const CHANNEL_LEGACY = {
    smm: 'organic', targeting: 'meta', bot: 'organic', production: 'organic',
    branding: 'organic', website: 'organic', ai: 'organic', consulting: 'organic',
};
const CRM_LEGACY = {
    no_marketing: 'q_crm_no',
    has_no_results: 'q_crm_sheet',
    has_wants_scale: 'q_crm_yes',
};
const SHORT_CHANNEL = new Set(['meta', 'google', 'telegram', 'organic', 'offline', 'none']);

function normalizeVertical(v) {
    if (!v) return null;
    if (v.startsWith('q_v_')) return v;
    return VERTICAL_LEGACY[v] || 'q_v_other';
}
function normalizeSpend(v) {
    if (!v) return null;
    if (v.startsWith('q_spend_')) return v;
    return SPEND_LEGACY[v] || null;
}
function normalizeChannels(arr) {
    if (!Array.isArray(arr)) return [];
    const out = [];
    const seen = new Set();
    for (const v of arr) {
        if (!v) continue;
        let key;
        if (v.startsWith('q_ch_')) key = v;
        else if (SHORT_CHANNEL.has(v)) key = 'q_ch_' + v;
        else key = 'q_ch_' + (CHANNEL_LEGACY[v] || 'organic');
        if (seen.has(key)) continue;
        seen.add(key);
        out.push(key.replace('q_ch_', ''));
    }
    return out;
}
function normalizeCrm(v) {
    if (!v) return null;
    if (v.startsWith('q_crm_')) return v;
    return CRM_LEGACY[v] || null;
}

// ── Admin notification labels (mirror of bot/handlers/questionnaire.py) ──
const VERTICAL_LABELS = {
    q_v_realestate: 'Жилая недвижимость / девелопмент',
    q_v_clinic: 'Частная медицинская клиника',
    q_v_education: 'Образование / коучинг',
    q_v_other: 'Другое направление',
};
const SPEND_LABELS = {
    q_spend_none: 'Реклама пока не запущена',
    q_spend_lt1k: 'До $1 000',
    q_spend_1k_3k: '$1 000 — $3 000',
    q_spend_3k_10k: '$3 000 — $10 000',
    q_spend_10k_plus: '$10 000+',
};
const CHANNEL_LABELS = {
    meta: 'Meta Ads', google: 'Google Ads', telegram: 'Telegram',
    organic: 'Органический контент', offline: 'Офлайн', none: 'Ничего не работает',
};
const CRM_LABELS = {
    q_crm_yes: 'Полноценная CRM',
    q_crm_sheet: 'Excel / Google Sheets',
    q_crm_no: 'Учёта нет',
};

const escape = (s) => String(s ?? '—').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

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
    const { initData, payload } = req.body || {};
    if (typeof initData !== 'string' || !payload || typeof payload !== 'object') {
        res.status(400).json({ error: 'bad_payload' });
        return;
    }
    const user = verifyInitData(initData, BOT_TOKEN);
    if (!user || !user.id) {
        res.status(401).json({ error: 'invalid_init_data' });
        return;
    }
    const telegramId = user.id;

    let twaLang = payload.lang === 'ru' ? 'ru' : 'uz';

    const updates = { preferred_lang: twaLang };
    const vertical = normalizeVertical(payload.business_type);
    if (vertical) updates.business_type = vertical;
    const spend = normalizeSpend(payload.budget_range);
    if (spend) updates.budget_range = spend;
    const channels = normalizeChannels(payload.service_interest);
    if (channels.length) updates.service_interest = channels;
    const crm = normalizeCrm(payload.current_marketing);
    if (crm) updates.current_marketing = crm;
    if (payload.phone) updates.phone = payload.phone;
    if (payload.name) updates.first_name = payload.name;
    if (payload.business_name) updates.business_name = payload.business_name;
    if (payload.website) updates.website = payload.website;
    if (payload.social_handle) updates.social_handle = payload.social_handle;

    updates.questionnaire_completed = true;
    updates.questionnaire_completed_at = new Date().toISOString();
    updates.questionnaire_step = 7;

    // Ensure lead row exists, then update
    await supabaseRequest('leads', 'POST', {
        telegram_id: telegramId,
        first_name: user.first_name || null,
        last_name: user.last_name || null,
        username: user.username || null,
        language_code: user.language_code || null,
    }).catch(() => {});
    const updated = await supabaseRequest(
        `leads?telegram_id=eq.${telegramId}`,
        'PATCH',
        updates,
    );
    await supabaseRequest('events', 'POST', {
        telegram_id: telegramId,
        event_type: 'twa_questionnaire_complete',
        event_data: {
            business_type: payload.business_type,
            services: payload.service_interest,
        },
    });

    // Build admin notification (mirror of _notify_admins_qualified)
    const lead = (Array.isArray(updated) && updated[0]) || updates;
    const name = escape(
        [user.first_name, user.last_name].filter(Boolean).join(' ') || '—',
    );
    const username = escape(user.username || '—');
    const verticalLbl = escape(VERTICAL_LABELS[lead.business_type] || '—');
    const spendLbl = escape(SPEND_LABELS[lead.budget_range] || '—');
    const channelsLbl = escape(
        (lead.service_interest || []).map((c) => CHANNEL_LABELS[c] || c).join(', ') || '—',
    );
    const crmLbl = escape(CRM_LABELS[lead.current_marketing] || '—');
    const biz = escape(lead.business_name || '—');
    const web = escape(lead.website || '—');
    const social = escape(lead.social_handle || '—');
    const phone = escape(lead.phone || '—');
    const source = escape(lead.source || 'organic');
    const score = lead.lead_score || 0;

    const adminText =
        `<b>Новая заявка — анкета пройдена</b>\n\n` +
        `Имя: <b>${name}</b> (@${username})\n` +
        `Направление: ${verticalLbl}\n` +
        `Бюджет на рекламу: ${spendLbl}\n` +
        `Каналы: ${channelsLbl}\n` +
        `CRM: ${crmLbl}\n` +
        `<b>Бизнес:</b> ${biz}\n` +
        `<b>Сайт:</b> ${web}\n` +
        `<b>Соцсети:</b> ${social}\n` +
        `Телефон: ${phone}\n` +
        `Источник: ${source}\n` +
        `Баллы: ${score}`;

    const adminIds = ADMIN_IDS.split(',').map((s) => s.trim()).filter(Boolean);
    await Promise.allSettled(adminIds.map((id) => tgSend(BOT_TOKEN, id, adminText)));

    res.status(200).json({ ok: true });
}
