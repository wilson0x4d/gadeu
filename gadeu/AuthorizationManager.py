# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT

from .handlers.AuthorizationHandler import AuthorizationHandler
from .AuthorizationMethod import AuthorizationMethod


class AuthorizationManager:

    __handlers:dict[AuthorizationMethod, AuthorizationHandler]
    __instance:'AuthorizationManager' = None

    def __init__(self):
        self.__handlers = dict[AuthorizationMethod, AuthorizationHandler]()

    @classmethod
    def instance(cls) -> 'AuthorizationManager':
        if cls.__instance is None:
            cls.__instance = AuthorizationManager()
        return cls.__instance

    def setAuthorizationHandler(self, authorizationMethod:AuthorizationMethod, handler:AuthorizationHandler|None) -> None:
        if handler is None:
            self.__handlers.pop(authorizationMethod, None)
        else:
            self.__handlers[authorizationMethod] = handler

    def getAuthorizationHandler(self, authorizationMethod:AuthorizationMethod) -> AuthorizationHandler|None:
        return self.__handlers.get(authorizationMethod, None)
