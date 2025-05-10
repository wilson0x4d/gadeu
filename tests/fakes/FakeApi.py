# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT
##

from datetime import datetime
import json
from uuid import UUID
import tornado
from gadeu import *


_d = dict[int,str]()


type FakeObj = FakeObj
class FakeObj:
    """An object composed of attributes."""
    one:int
    two:str
    three:UUID
    four:datetime
    five:float
    six:bool
    # self-referencing objects
    # TODO: what about stringified type  ie. 'FakeObj'
    seven:FakeObj
    # TODO: array (list) types?
    eight:list[bool]
    # TODO: map (dictionary) types?
    nine:dict[str,UUID]
    # TODO: tuples?
    ten:tuple[str,int,UUID]


class FakePropertyObj:
    """An object composed of properties."""

    _foo:str
    __bar:str
    __bleh:datetime

    def __init__(self) -> None:
        self._foo = None
        self.__bar = None

    @property
    def foo(self) -> str:
        """A read-only property"""
        return self._foo

    @property
    def bar(self) -> int:
        """A read-write property"""
        return self.__bar
    @bar.setter
    def bar(self, value:int) -> None:
        self.__bar = value

    @property
    def bleh(self) -> datetime:
        """A datetime property"""
        return self.__bleh
    @bleh.setter
    def bleh(self, value:datetime) -> None:
        self.__bleh = value


class FakeApi(tornado.web.RequestHandler):    

    def initialize(self) -> None:
        pass

    async def get(self, id:str) -> None:
        self.set_status(200)
        self.write(_d.get(id, ''))

    @authorization.apiKey
    async def put(self, id:str, name:str) -> None:
        claims = self.request.arguments.get('claims', None)
        if claims.get('can_edit', False) != True:
            raise tornado.web.HTTPError(403)
        _d[id] = name
        self.set_status(204)

    @authorization.apiKey
    async def delete(self, name:str) -> None:
        id = None
        for k,v in _d.items():
            if v == name:
                id = k
        if id is not None:
            _d.pop(id, None)
        self.set_status(200)

    @authorization.bearerToken
    async def post(self) -> None:
        # NOTE: echo endpoint
        buf = self.request.body
        d = json.loads(buf)
        _d[d['id']] = d['name']
        self.set_status(204)
