import { createFileRoute } from "@tanstack/react-router";

async function sha256Hex(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function safeEqual(a: string, b: string) {
  const [x, y] = await Promise.all([sha256Hex(a), sha256Hex(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i += 1) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}

const headers = { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" };

// Open in a browser: /api/public/generate-key?token=<admin password>
export const Route = createFileRoute("/api/public/generate-key")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const token = new URL(request.url).searchParams.get("token") ?? "";
        const expected = process.env["ZIMADMIN_PASSWORD"];
        if (!expected) return new Response("Key generation unavailable.", { status: 503, headers });
        if (!token || !(await safeEqual(token.trim().toLowerCase(), expected.trim().toLowerCase()))) {
          return new Response("Unauthorized.", { status: 401, headers });
        }

        const bytes = crypto.getRandomValues(new Uint8Array(16));
        const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
        const key = `ZIM-${hex.match(/.{4}/g)?.join("-") ?? hex}`;

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { error } = await supabaseAdmin.from("access_keys").insert({ key_hash: await sha256Hex(key) });
        if (error) return new Response("Couldn't create a key. Try again.", { status: 500, headers });

        return new Response(key, { status: 200, headers });
      },
    },
  },
});
