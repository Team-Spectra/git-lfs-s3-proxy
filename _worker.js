import { AwsClient } from "aws4fetch";

const HOMEPAGE = "https://github.com/milkey-mouse/git-lfs-s3-proxy";
const EXPIRY = 3600;

const MIME = "application/vnd.git-lfs+json";

const METHOD_FOR = {
  upload: "PUT",
  download: "GET",
};

async function sign(s3, bucket, path, method) {
  const info = { method };
  const signed = await s3.sign(
    new Request(`https://${bucket}/${path}?X-Amz-Expires=${EXPIRY}`, info),
    { aws: { signQuery: true } },
  );
  return signed.url;
}

// Cloudflare limits a free invocation to 50 subrequests; existence checks stay below it.
const MAX_EXISTENCE_CHECKS = 40;

async function exists(s3, bucket, oid, size) {
  try {
    const res = await s3.fetch(`https://${bucket}/${oid}`, { method: "HEAD" });
    return res.ok && Number(res.headers.get("Content-Length")) === size;
  } catch {
    return false;
  }
}

// With R2_KEY_ID / R2_SECRET set on the site, downloads need no credentials and uploads
// need PUSH_PASSWORD or that same R2 key; without them, clients send their own R2 key.
function credentialsFor(auth, env, operation) {
  if (!env.R2_KEY_ID || !env.R2_SECRET) {
    if (!auth) {
      throw new Response(null, { status: 401 });
    }
    return { accessKeyId: auth.user, secretAccessKey: auth.pass };
  }

  const own = { accessKeyId: env.R2_KEY_ID, secretAccessKey: env.R2_SECRET };
  if (operation === "download") {
    return own;
  }

  const byPassword = !!auth && !!env.PUSH_PASSWORD && auth.pass === env.PUSH_PASSWORD;
  const byKey = !!auth && auth.user === env.R2_KEY_ID && auth.pass === env.R2_SECRET;
  if (!byPassword && !byKey) {
    throw new Response(null, { status: 401 });
  }
  return own;
}

function parseAuthorization(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return null;
  }

  const [scheme, encoded] = auth.split(" ");
  if (scheme !== "Basic" || !encoded) {
    throw new Response(null, { status: 400 });
  }

  const buffer = Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
  const decoded = new TextDecoder().decode(buffer);
  const index = decoded.indexOf(":");
  if (index === -1) {
    throw new Response(null, { status: 400 });
  }

  return { user: decoded.slice(0, index), pass: decoded.slice(index + 1) };
}

async function fetch(req, env) {
  const url = new URL(req.url);

  if (url.pathname == "/") {
    if (req.method === "GET") {
      return Response.redirect(HOMEPAGE, 302);
    } else {
      return new Response(null, { status: 405, headers: { Allow: "GET" } });
    }
  }

  if (!url.pathname.endsWith("/objects/batch")) {
    return new Response(null, { status: 404 });
  }

  if (req.method !== "POST") {
    return new Response(null, { status: 405, headers: { Allow: "POST" } });
  }

  // in practice, we'd rather not break out-of-spec clients not setting these
  /*if (!req.headers.get("Accept").startsWith(MIME)
    || !req.headers.get("Content-Type").startsWith(MIME)) {
    return new Response(null, { status: 406 });
  }*/

  const { objects, operation, hash_algo = "sha256" } = await req.json();
  const credentials = credentialsFor(parseAuthorization(req), env, operation);

  // The oid becomes the object key in a signed URL: anything but a hash could sign a listing.
  if (!METHOD_FOR[operation] || !objects.every(({ oid }) => /^[0-9a-f]{64}$/.test(oid))) {
    return new Response(null, { status: 422 });
  }
  let s3Options = {};

  const segments = url.pathname.split("/").slice(1, -2);
  let params = {};
  let bucketIdx = 0;
  for (const segment of segments) {
    const sliceIdx = segment.indexOf("=");
    if (sliceIdx === -1) {
      break;
    } else {
      const key = decodeURIComponent(segment.slice(0, sliceIdx));
      const val = decodeURIComponent(segment.slice(sliceIdx + 1));
      s3Options[key] = val;

      bucketIdx++;
    }
  }

  const s3 = new AwsClient({ ...s3Options, ...credentials });
  const bucket = segments.slice(bucketIdx).join("/");
  const expires_in = params.expiry || env.EXPIRY || EXPIRY;

  if (hash_algo !== "sha256") {
    return new Response(
      JSON.stringify({
        message: `Hash algorithm '${hash_algo}' is not supported. Only 'sha256' is currently supported.`,
      }),
      {
        status: 409,
        headers: { "Content-Type": "application/vnd.git-lfs+json" },
      },
    );
  }

  const method = METHOD_FOR[operation];
  const checkExisting =
    operation === "upload" && objects.length <= MAX_EXISTENCE_CHECKS;
  const response = JSON.stringify({
    transfer: "basic",
    hash_algo: "sha256",
    objects: await Promise.all(
      objects.map(async ({ oid, size }) => {
        // An object without actions is one the server already has.
        if (checkExisting && (await exists(s3, bucket, oid, size))) {
          return { oid, size, authenticated: true };
        }
        return {
          oid,
          size,
          authenticated: true,
          actions: {
            [operation]: {
              href: await sign(s3, bucket, oid, method),
              expires_in,
            },
          },
        };
      }),
    ),
  });

  return new Response(response, {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/vnd.git-lfs+json",
    },
  });
}

// Thrown Responses must be returned, not left uncaught (Cloudflare error 1101).
// A 401 with WWW-Authenticate makes git-lfs ask the credential helper for the keys.
async function handle(req, env) {
  try {
    return await fetch(req, env);
  } catch (e) {
    if (!(e instanceof Response)) {
      throw e;
    }
    if (e.status === 401) {
      return new Response(null, {
        status: 401,
        headers: { "WWW-Authenticate": 'Basic realm="git-lfs"' },
      });
    }
    return e;
  }
}

export default { fetch: handle };
