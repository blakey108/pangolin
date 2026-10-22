import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import { db, idp, idpOidcConfig } from "@server/db";
import response from "@server/lib/response";
import HttpCode from "@server/types/HttpCode";
import createHttpError from "http-errors";
import logger from "@server/logger";
import { fromError } from "zod-validation-error";
import { and, eq } from "drizzle-orm";
import jsonwebtoken from "jsonwebtoken";
import config from "@server/lib/config";
import { decrypt } from "@server/lib/crypto";
import {
    EntraTokenError,
    exchangeRdpEntraCode,
    fetchEntraNonce,
    rdpEntraRedirectUrl,
    rdpEntraScope
} from "@server/lib/idp/entraRdp";
import { RDP_ENTRA_STATE_PURPOSE } from "./generateRdpEntraUrl";

const paramsSchema = z
    .object({
        idpId: z.coerce.number<number>()
    })
    .strict();

const bodySchema = z.strictObject({
    code: z.string().nonempty(),
    state: z.string().nonempty()
});

const stateSchema = z.object({
    purpose: z.literal(RDP_ENTRA_STATE_PURPOSE),
    idpId: z.number(),
    state: z.string(),
    codeVerifier: z.string(),
    reqCnf: z.string(),
    deviceName: z.string(),
    origin: z.string()
});

export type ValidateRdpEntraCallbackResponse = {
    accessToken: string;
    nonce: string;
    deviceName: string;
    origin: string;
};

/**
 * Completes the Entra RDP sign-in: exchanges the code for a token bound to the
 * RDP client's key and fetches the Entra nonce the RDP assertion must carry.
 */
export async function validateRdpEntraCallback(
    req: Request,
    res: Response,
    next: NextFunction
): Promise<any> {
    try {
        const parsedParams = paramsSchema.safeParse(req.params);
        if (!parsedParams.success) {
            return next(
                createHttpError(
                    HttpCode.BAD_REQUEST,
                    fromError(parsedParams.error).toString()
                )
            );
        }

        const parsedBody = bodySchema.safeParse(req.body);
        if (!parsedBody.success) {
            return next(
                createHttpError(
                    HttpCode.BAD_REQUEST,
                    fromError(parsedBody.error).toString()
                )
            );
        }

        const { idpId } = parsedParams.data;
        const { code, state } = parsedBody.data;

        const key = config.getRawConfig().server.secret!;

        let decodedState: unknown;
        try {
            decodedState = jsonwebtoken.verify(state, key);
        } catch (err) {
            logger.warn("Invalid Entra RDP state", { err });
            return next(
                createHttpError(
                    HttpCode.BAD_REQUEST,
                    "Invalid or expired state"
                )
            );
        }

        const parsedState = stateSchema.safeParse(decodedState);
        if (!parsedState.success || parsedState.data.idpId !== idpId) {
            return next(createHttpError(HttpCode.BAD_REQUEST, "Invalid state"));
        }

        const { codeVerifier, reqCnf, deviceName, origin } = parsedState.data;

        const [existingIdp] = await db
            .select()
            .from(idp)
            .innerJoin(idpOidcConfig, eq(idpOidcConfig.idpId, idp.idpId))
            .where(and(eq(idp.type, "oidc"), eq(idp.idpId, idpId)));

        if (!existingIdp) {
            return next(createHttpError(HttpCode.NOT_FOUND, "IdP not found"));
        }

        const clientId = decrypt(existingIdp.idpOidcConfig.clientId, key);
        const clientSecret = decrypt(
            existingIdp.idpOidcConfig.clientSecret,
            key
        );
        const tokenUrl = existingIdp.idpOidcConfig.tokenUrl;

        let accessToken: string;
        let nonce: string;
        try {
            const tokens = await exchangeRdpEntraCode({
                tokenUrl,
                clientId,
                clientSecret,
                redirectUri: rdpEntraRedirectUrl(idpId),
                code,
                codeVerifier,
                scope: rdpEntraScope(deviceName),
                reqCnf
            });
            accessToken = tokens.accessToken;
            nonce = await fetchEntraNonce(tokenUrl);
        } catch (err) {
            if (err instanceof EntraTokenError) {
                logger.warn("Entra RDP token request failed", {
                    code: err.code,
                    message: err.message
                });
                return next(createHttpError(HttpCode.BAD_GATEWAY, err.message));
            }
            throw err;
        }

        return response<ValidateRdpEntraCallbackResponse>(res, {
            data: {
                accessToken,
                nonce,
                deviceName,
                origin
            },
            success: true,
            error: false,
            message: "Entra RDP sign-in completed",
            status: HttpCode.OK
        });
    } catch (error) {
        logger.error(error);
        return next(
            createHttpError(
                HttpCode.INTERNAL_SERVER_ERROR,
                "An error occurred while completing the sign-in"
            )
        );
    }
}
