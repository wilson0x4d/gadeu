# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import Callable
import tornado

from ..AuthorizationMethod import AuthorizationMethod
from ..TokenUtil import TokenUtil
from .AuthorizationHandler import AuthorizationHandler


class BearerTokenAuthorizationHandler(AuthorizationHandler):

    __claimsArgumentName:str
    __key:str
    __name:str
    __validator:Callable[[str, dict[str,str]],bool]

    def __init__(self, key:str, validator:Callable[[str, dict[str,str]],bool] = lambda t,c: True, name:str = 'Bearer', claimsArgumentName:str = 'claims'):
        super().__init__()
        self.__claimsArgumentName = claimsArgumentName
        self.__key = key
        self.__name = name
        self.__validator = validator

    def authorize(self, requestHandler:tornado.web.RequestHandler) -> None:
        bearer:str = requestHandler.request.headers.get('Authorization', None)
        if bearer is None:
            raise tornado.web.HTTPError(403, 'No Authorization')
        token:str = bearer.replace(self.__name, '').strip()
        claims:dict[str,str] = None
        try:
            claims = TokenUtil.getTokenClaims(self.__key, token, AuthorizationMethod.BEARERTOKEN)
            if self.__claimsArgumentName is not None:
                requestHandler.request.arguments[self.__claimsArgumentName] = claims
        except:
            raise tornado.web.HTTPError(403, 'Authorization Fail')
        if not self.__validator(token, claims):
            raise tornado.web.HTTPError(403, 'Not Authorized')
