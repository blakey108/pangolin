import config from "@server/lib/config";

/**
 * Helpers for Microsoft Entra ID sign-in to RDP hosts (RDS AAD Auth).
 *
 * The browser RDP client authenticates to Entra joined Windows hosts with an
 * access token issued for the "Microsoft Remote Desktop" resource and bound to
 * an RSA proof-of-possession key held by the browser. The token is obtained
 * through the regular authorization code flow of an Entra OIDC identity
 * provider configured in Pangolin, with two additions: the RDP scope and the
 * `req_cnf` parameter that binds the token to the key.
 */

const ENTRA_AUTHORITY_SUFFIXES = [
    "login.microsoftonline.com",
    "login.microsoftonline.us",
    "login.microsoftonline.de",
    "login.partner.microsoftonline.cn",
    "login.windows.net"
];

const RDP_TOKEN_AUDIENCE = "ms-device-service://termsrv.wvd.microsoft.com";

/** Entra device names are NetBIOS-style computer names. */
const DEVICE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

export function isEntraAuthority(authUrl: string): boolean {
    try {
        const { hostname } = new URL(authUrl);
        return ENTRA_AUTHORITY_SUFFIXES.some(
            (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`)
        );
    } catch {
        return false;
    }
}

export function isValidEntraDeviceName(name: string): boolean {
    return DEVICE_NAME_PATTERN.test(name);
}

/** Scope of the access token for one target host. */
export function rdpEntraScope(deviceName: string): string {
    return `${RDP_TOKEN_AUDIENCE}/name/${deviceName}/user_impersonation`;
}

/** Redirect URI registered on the Entra app registration for RDP sign-in. */
export function rdpEntraRedirectUrl(idpId: number): string {
    const baseUrl = config.getRawConfig().app.dashboard_url!;
    return new URL(`/auth/idp/${idpId}/rdp/callback`, baseUrl).toString();
}

export type RdpEntraTokens = {
    accessToken: string;
    expiresIn: number | null;
};

export class EntraTokenError extends Error {
    constructor(
        message: string,
        public readonly code?: string
    ) {
        super(message);
        this.name = "EntraTokenError";
    }
}

/**
 * Exchanges the authorization code for a proof-of-possession access token.
 *
 * `reqCnf` is the base64url `{"kid": <RFC 7638 thumbprint>}` of the browser's
 * key; Entra echoes it as the `cnf` claim of the token.
 */
export async function exchangeRdpEntraCode(params: {
    tokenUrl: string;
    clientId: string;
    clientSecret: string;
    redirectUri: string;
    code: string;
    codeVerifier: string;
    scope: string;
    reqCnf: string;
}): Promise<RdpEntraTokens> {
    const body = new URLSearchParams({
        client_id: params.clientId,
        client_secret: params.clientSecret,
        grant_type: "authorization_code",
        code: params.code,
        redirect_uri: params.redirectUri,
        code_verifier: params.codeVerifier,
        scope: params.scope,
        token_type: "pop",
        req_cnf: params.reqCnf
    });

    const json = await postForm(params.tokenUrl, body);

    if (typeof json.access_token !== "string") {
        throw new EntraTokenError(
            "Entra ID did not return an access token",
            typeof json.error === "string" ? json.error : undefined
        );
    }

    if (json.token_type !== "pop") {
        // Without the binding the RDP host rejects the assertion, so fail here
        // with a message that points at the tenant configuration.
        throw new EntraTokenError(
            "Entra ID issued a bearer token instead of a proof-of-possession token; the app registration is not approved for Remote Desktop sign-in"
        );
    }

    return {
        accessToken: json.access_token,
        expiresIn: typeof json.expires_in === "number" ? json.expires_in : null
    };
}

/** Fresh Entra nonce that the RDP assertion must carry (grant_type=srv_challenge). */
export async function fetchEntraNonce(tokenUrl: string): Promise<string> {
    const json = await postForm(
        tokenUrl,
        new URLSearchParams({ grant_type: "srv_challenge" })
    );

    if (typeof json.Nonce !== "string") {
        throw new EntraTokenError("Entra ID did not return a nonce");
    }

    return json.Nonce;
}

async function postForm(
    url: string,
    body: URLSearchParams
): Promise<Record<string, unknown>> {
    let response: Response;
    try {
        response = await fetch(url, {
            method: "POST",
            headers: {
                "Content-Type": "application/x-www-form-urlencoded",
                Accept: "application/json"
            },
            body
        });
    } catch (error) {
        throw new EntraTokenError(
            `Unable to reach Entra ID: ${error instanceof Error ? error.message : String(error)}`
        );
    }

    let json: Record<string, unknown>;
    try {
        json = (await response.json()) as Record<string, unknown>;
    } catch {
        throw new EntraTokenError(
            `Entra ID returned an unexpected response (HTTP ${response.status})`
        );
    }

    if (!response.ok) {
        const description =
            typeof json.error_description === "string"
                ? json.error_description
                : `HTTP ${response.status}`;
        throw new EntraTokenError(
            `Entra ID rejected the request: ${description}`,
            typeof json.error === "string" ? json.error : undefined
        );
    }

    return json;
}
