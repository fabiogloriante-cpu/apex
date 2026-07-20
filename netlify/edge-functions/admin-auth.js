function unauthorized(message = "Accesso riservato") {
  return new Response(message, {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="APEX Gestione Articoli", charset="UTF-8"',
      "Cache-Control": "no-store",
      "Content-Type": "text/plain; charset=utf-8",
    },
  });
}

export default async (request, context) => {
  const expectedUser = Deno.env.get("APEX_ADMIN_USER");
  const expectedPassword = Deno.env.get("APEX_ADMIN_PASSWORD");

  if (!expectedUser || !expectedPassword) {
    return new Response("Protezione amministratore non configurata.", {
      status: 503,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const authorization = request.headers.get("authorization");
  if (!authorization?.startsWith("Basic ")) return unauthorized();

  try {
    const decoded = atob(authorization.slice(6));
    const separator = decoded.indexOf(":");
    const username = decoded.slice(0, separator);
    const password = decoded.slice(separator + 1);

    if (separator < 0 || username !== expectedUser || password !== expectedPassword) {
      return unauthorized("Nome utente o password non corretti.");
    }
  } catch {
    return unauthorized();
  }

  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store");
  headers.set("X-Robots-Tag", "noindex, nofollow");
  return new Response(response.body, { status: response.status, headers });
};

