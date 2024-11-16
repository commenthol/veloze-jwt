export function decodeBase64(input: string): string;
export function decodeJwt(token: string): DecodedJWT;
export type DecodedJWT = {
    header: {
        kid: string;
        alg: string;
    };
    payload: {
        iat: number;
        exp: number;
        [prop: string]: any;
    };
    signature: string;
};
