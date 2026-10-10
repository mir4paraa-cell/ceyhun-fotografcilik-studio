
const crypto = require("crypto");

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  TURNSTILE_SECRET_KEY,
  PHONE_HASH_SECRET,
} = process.env;

function send(res, status, data) {
  return res.status(status).json(data);
}

function normalizePhone(value) {
  let phone = String(value || "").replace(/\D/g, "");

  if (phone.startsWith("0090")) phone = phone.slice(4);
  else if (phone.startsWith("90")) phone = phone.slice(2);
  else if (phone.startsWith("0")) phone = phone.slice(1);

  if (!/^5\d{9}$/.test(phone)) return null;

  return "+90" + phone;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(res, 405, { error: "Yalnızca POST isteği kabul edilir." });
  }

  if (
    !SUPABASE_URL ||
    !SUPABASE_SERVICE_ROLE_KEY ||
    !TURNSTILE_SECRET_KEY ||
    !PHONE_HASH_SECRET
  ) {
    return send(res, 500, {
      error: "Sunucu ayarları eksik. Vercel ortam değişkenlerini kontrol edin.",
    });
  }

  try {
    const { name, phone, weddingDate, turnstileToken } = req.body || {};
    const customerName = String(name || "").trim();
    const normalizedPhone = normalizePhone(phone);

    if (customerName.length < 2 || customerName.length > 100) {
      return send(res, 400, { error: "Lütfen geçerli adınızı yazın." });
    }

    if (!normalizedPhone) {
      return send(res, 400, {
        error: "Geçerli bir Türkiye cep telefonu numarası girin.",
      });
    }

    if (
      !/^\d{4}-\d{2}-\d{2}$/.test(String(weddingDate || "")) ||
      Number.isNaN(Date.parse(weddingDate + "T12:00:00Z"))
    ) {
      return send(res, 400, { error: "Lütfen geçerli bir tarih seçin." });
    }

    if (!turnstileToken || typeof turnstileToken !== "string") {
      return send(res, 400, {
        error: "Güvenlik doğrulamasını tamamlayın.",
      });
    }

    const verificationBody = new URLSearchParams({
      secret: TURNSTILE_SECRET_KEY,
      response: turnstileToken,
    });

    const verification = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: verificationBody,
      }
    );

    if (!verification.ok) {
      return send(res, 502, {
        error: "Güvenlik doğrulaması şu anda yapılamıyor. Tekrar deneyin.",
      });
    }

    const verificationResult = await verification.json();

    if (!verificationResult.success) {
      return send(res, 403, {
        error: "Güvenlik doğrulaması başarısız. Lütfen tekrar deneyin.",
      });
    }

    const expectedHost = new URL(SUPABASE_URL).hostname;
    if (!expectedHost.endsWith(".supabase.co")) {
      return send(res, 500, { error: "Sunucu yapılandırması hatalı." });
    }

    const phoneHash = crypto
      .createHmac("sha256", PHONE_HASH_SECRET)
      .update(normalizedPhone)
      .digest("hex");

    const rpcResponse = await fetch(
      SUPABASE_URL.replace(/\/+$/, "") +
        "/rest/v1/rpc/cs_wheel_spin",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          apikey: SUPABASE_SERVICE_ROLE_KEY,
          Authorization: "Bearer " + SUPABASE_SERVICE_ROLE_KEY,
        },
        body: JSON.stringify({
          p_phone_hash: phoneHash,
          p_customer_name: customerName,
          p_wedding_date: weddingDate,
        }),
      }
    );

    const responseText = await rpcResponse.text();
    let result;

    try {
      result = responseText ? JSON.parse(responseText) : {};
    } catch {
      result = {};
    }

    if (!rpcResponse.ok) {
      console.error("Wheel RPC error:", rpcResponse.status, result);

      if (rpcResponse.status === 409) {
        return send(res, 409, {
          error: "Bu telefon numarasıyla daha önce çark çevrilmiş.",
        });
      }

      return send(res, 500, {
        error: "Çark şu anda çalışmıyor. Lütfen biraz sonra tekrar deneyin.",
      });
    }

    if (Array.isArray(result)) result = result[0] || {};

    const rewardKey = result.reward_key || result.reward || result.status;

    if (!rewardKey) {
      console.error("Unexpected wheel RPC result:", result);
      return send(res, 500, {
        error: "Ödül sonucu okunamadı. Veritabanı dönüşünü kontrol etmek gerekiyor.",
      });
    }

    if (String(rewardKey).toLowerCase() === "thanks") {
      return send(res, 200, {
        success: true,
        reward_key: "thanks",
        message: "Kampanyadaki ödül kontenjanı doldu. Katıldığınız için teşekkürler!",
      });
    }

    if (!result.coupon_code || !result.expires_at) {
      console.error("Missing coupon fields:", result);
      return send(res, 500, {
        error: "Kupon bilgisi oluşturulamadı. Lütfen yöneticiyle iletişime geçin.",
      });
    }

    return send(res, 200, {
      success: true,
      reward_key: rewardKey,
      coupon_code: result.coupon_code,
      expires_at: result.expires_at,
    });
  } catch (error) {
    console.error("Wheel API error:", error);
    return send(res, 500, {
      error: "Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin.",
    });
  }
};
