export function decodeBase64(input: string): string;
export function decodeJwt(token: string): DecodedJWT;
export type DecodedJWT = {
    header: {
        kid: string;
        alg: string;
    };
    payload: {
        [prop: string]: any;
        iat: number;
        exp: number;
    };
    signature: string;
};
