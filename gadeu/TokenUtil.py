# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT

import os
import base58
import hashlib
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

from .AuthorizationMethod import AuthorizationMethod

class TokenUtil:
    """A class that can create and verify cryptographically secure tokens."""

    def __init__(self) -> None:
        pass

    def __createAesKey(self) -> str:
        key = os.urandom(32)
        return base58.b58encode(key).decode()

    def __createJwk(self) -> str:
        import jwcrypto.jwk as jwk
        jkey = jwk.JWK(generate='oct', size=256)
        key:str = jkey.export()
        return base58.b58encode(key).decode()

    def __createApiKeyToken(self, key:bytes, claims:dict[str,str]) -> str:
        blockSizeBits = 128
        blockSizeBytes = int(blockSizeBits/8)
        iv = hashlib.shake_128(key, usedforsecurity=True).digest(blockSizeBytes)
        cbc = Cipher(algorithms.AES256(key), modes.CBC(iv)).encryptor()
        padder = padding.PKCS7(blockSizeBits).padder()
        input = padder.update(json.dumps(claims).encode()) + padder.finalize()
        output = cbc.update(input) + cbc.finalize()
        result = base58.b58encode(output).decode()
        mid = int(len(result)/2)
        return result[0:mid] + '.' + result[mid:]

    def __createBearerToken(self, key:bytes, claims:dict[str,str]) -> str:
        import jwcrypto.jwk as jwk
        import jwcrypto.jwt as jwt
        jkey = jwk.JWK(**json.loads(key))
        stoken = jwt.JWT(header={'alg':'HS256'}, claims=claims)
        stoken.make_signed_token(jkey)
        etoken = jwt.JWT(header={'alg':'A256KW', 'enc':'A256CBC-HS512'}, claims=stoken.serialize())
        etoken.make_encrypted_token(jkey)
        return etoken.serialize()

    def __getApiKeyTokenClaims(self, key:bytes, token:str) -> dict[str,str]:
        blockSizeBits = 128
        blockSizeBytes = int(blockSizeBits/8)
        buf = base58.b58decode(token.replace('.',''))
        iv = hashlib.shake_128(key, usedforsecurity=True).digest(blockSizeBytes)
        cbc = Cipher(algorithms.AES256(key), modes.CBC(iv)).decryptor()
        output = cbc.update(buf) + cbc.finalize()
        unpadder = padding.PKCS7(blockSizeBits).unpadder()
        result = unpadder.update(output) + unpadder.finalize()
        return json.loads(result)

    def __getBearerTokenClaims(self, key:bytes, token:str) -> str:
        import jwcrypto.jwk as jwk
        import jwcrypto.jwt as jwt
        jkey = jwk.JWK(**json.loads(key))
        etoken = jwt.JWT(key=jkey, jwt=token, expected_type='JWE')
        stoken = jwt.JWT(key=jkey, jwt=etoken.claims)
        return json.loads(stoken.claims)

    def createTokenKey(self, authorizationMethod:AuthorizationMethod) -> str:
        match authorizationMethod:
            case AuthorizationMethod.APIKEY:
                return self.__createAesKey()
            case AuthorizationMethod.BEARERTOKEN:
                return self.__createJwk()
            case _:
                raise Exception(f'Unsupported authorizationMethod "{authorizationMethod}"')

    def createToken(self, key:bytes|str, claims:dict[str,str], authorizationMethod:AuthorizationMethod) -> str:
        if type(key) is str:
            key = base58.b58decode(key.encode())
        match authorizationMethod:
            case AuthorizationMethod.APIKEY:
                return self.__createApiKeyToken(key, claims)
            case AuthorizationMethod.BEARERTOKEN:
                return self.__createBearerToken(key, claims)
            case _:
                raise Exception(f'Unsupported authorizationMethod "{authorizationMethod}"')

    def getTokenClaims(self, key:bytes|str, token:str, authorizationMethod:AuthorizationMethod) -> dict[str,str]:
        if type(key) is str:
            key = base58.b58decode(key.encode())
        match authorizationMethod:
            case AuthorizationMethod.APIKEY:
                return self.__getApiKeyTokenClaims(key, token)
            case AuthorizationMethod.BEARERTOKEN:
                return self.__getBearerTokenClaims(key, token)
            case _:
                raise Exception(f'Unsupported authorizationMethod "{authorizationMethod}"')
