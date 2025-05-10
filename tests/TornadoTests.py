# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT

from typing import Any
from gadeu import *
import json
from punit import *
import tornado
import urllib3

from .fakes.FakeApi import FakeApi

@fact
async def putRequiresApiKey() -> None:
    """Confirm that a basic tornado app can require an apiKey, when decorated and configured properly."""

    # generate a secret key for token generation/verification
    apiKeySecret = TokenUtil.createSecretKey(AuthorizationMethod.APIKEY)

    # faux validator to confirm validator is (or is not) being called
    validatorCallCount = 0
    def validator(token:str, claims:dict[str,Any]) -> bool:
        # bookkeeping for test assertions
        nonlocal validatorCallCount
        validatorCallCount += 1
        # globally, require `api_access` claim to be `true`
        if claims.get('api_access', False) != True:
            raise tornado.web.HTTPError(403)
        return True

    # configure an apiKey auth handler
    AuthorizationManager.setAuthorizationHandler(
        AuthorizationMethod.APIKEY,
        handlers.ApiKeyAuthorizationHandler(
            key=apiKeySecret,
            validator=validator))

    # basic Tornado app setup, with a "Fake API" handler
    app = tornado.web.Application()
    server = app.listen(port=3456, address='127.0.0.1')
    try:
        app.add_handlers('.*', [
            (r'/api/v2/fakes', FakeApi),
            (r'/api/v2/fakes/(?P<id>\d+)', FakeApi),
            (r'/api/v2/fakes/(?P<name>[\dA-Za-z]+)', FakeApi),
            (r'/api/v2/fakes/(?P<id>\d+)/(?P<name>[^/][\dA-Za-z]+)', FakeApi)
        ])

        # assert 'PUT' method fails without an apiKey, and that the validator was not called
        id = 1
        name = 'test'
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('PUT', f'http://127.0.0.1:3456/api/v2/fakes/{id}/{name}')
            assert response.status == 403, 'because no apiKey was provided.'
        assert validatorCallCount == 0
        # assert 'PUT' method succeeds with an apiKey, and that our validator was called
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('PUT', f'http://127.0.0.1:3456/api/v2/fakes/{id}/{name}', headers={
                'X-API-Key': TokenUtil.createToken(apiKeySecret, { 'api_access':True, 'can_edit':True }, AuthorizationMethod.APIKEY)
            })
            assert response.status == 204
        assert validatorCallCount == 1
        # assert 'GET' method does not require a token, and that our validator was not called a second time
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('GET', f'http://127.0.0.1:3456/api/v2/fakes/{id}')
            assert response.status == 200
            data:bytes = await response.data
            assert data is not None
            assert data.decode() == 'test'        
        assert validatorCallCount == 1
    finally:
        server.stop()


@fact
async def postRequiresBearerToken() -> None:
    """Confirm that a basic tornado app can require a Bearer token, when decorated and configured properly."""

    # generate a secret key for token generation/verification
    bearerTokenSecret = TokenUtil.createSecretKey(AuthorizationMethod.BEARERTOKEN)

    # faux validator to confirm validator is (or is not) being called
    validatorCallCount = 0
    def validator(token:str, claims:dict[str,Any]) -> bool:
        # bookkeeping for test assertions
        nonlocal validatorCallCount
        validatorCallCount += 1
        # globally, require `api_access` claim to be `true`
        if claims.get('api_access', False) != True:
            raise tornado.web.HTTPError(403)
        return True

    # configure a bearerToken auth handler
    AuthorizationManager.setAuthorizationHandler(
        AuthorizationMethod.BEARERTOKEN,
        handlers.BearerTokenAuthorizationHandler(
            key=bearerTokenSecret,
            validator=validator))

    # basic Tornado app setup, with a "Fake API" handler
    app = tornado.web.Application()
    server = app.listen(port=3457, address='127.0.0.1')
    try:
        app.add_handlers('.*', [
            (r'/api/v2/fakes', FakeApi),
            (r'/api/v2/fakes/(?P<id>\d+)', FakeApi),
            (r'/api/v2/fakes/(?P<name>[\dA-Za-z]+)', FakeApi),
            (r'/api/v2/fakes/(?P<id>\d+)/(?P<name>[^/][\dA-Za-z]+)', FakeApi)
        ])

        # assert 'POST' method fails without an bearerToken, and that the validator was not called
        id = '1'
        name = 'test'
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request(
                'POST', f'http://127.0.0.1:3457/api/v2/fakes',
                body=json.dumps({
                    'id': id,
                    'name': name
                }))
            assert response.status == 403, 'because no bearerToken was provided.'
        assert validatorCallCount == 0
        # assert 'POST' method succeeds with a bearerToken, and that our validator was called
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request(
                'POST', f'http://127.0.0.1:3457/api/v2/fakes',
                headers={
                    'Authorization': f'Bearer {TokenUtil.createToken(bearerTokenSecret, { 'api_access':True, 'can_edit':True }, AuthorizationMethod.BEARERTOKEN)}'
                },
                body=json.dumps({
                    'id': id,
                    'name': name
                }))
            assert response.status == 204
        assert validatorCallCount == 1
        # assert 'GET' method does not require a token, and that our validator was not called a second time
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('GET', f'http://127.0.0.1:3457/api/v2/fakes/{id}')
            assert response.status == 200
            data:bytes = await response.data
            assert data is not None
            assert data.decode() == 'test'
        assert validatorCallCount == 1
    finally:
        server.stop()

@fact
async def verifyMixedAuth() -> None:
    """Verify that a server can require a mixture of authentication methods."""

    # generate secret keys for token generation/verification
    bearerTokenSecret = TokenUtil.createSecretKey(AuthorizationMethod.BEARERTOKEN)
    apiKeySecret = TokenUtil.createSecretKey(AuthorizationMethod.APIKEY)

    # faux validator to confirm validator is (or is not) being called
    validatorCallCount = 0
    def validator(token:str, claims:dict[str,Any]) -> bool:
        # bookkeeping for test assertions
        nonlocal validatorCallCount
        validatorCallCount += 1
        # globally, require `api_access` claim to be `true`
        if claims.get('api_access', False) != True:
            raise tornado.web.HTTPError(403)
        return True

    # configure a bearerToken auth handler
    AuthorizationManager.setAuthorizationHandler(
        AuthorizationMethod.BEARERTOKEN,
        handlers.BearerTokenAuthorizationHandler(
            key=bearerTokenSecret,
            validator=validator))
    # configure an apiKey auth handler
    AuthorizationManager.setAuthorizationHandler(
        AuthorizationMethod.APIKEY,
        handlers.ApiKeyAuthorizationHandler(
            key=apiKeySecret,
            validator=validator))

    # basic Tornado app setup, with a "Fake API" handler
    app = tornado.web.Application()
    server = app.listen(port=3458, address='127.0.0.1')
    try:
        app.add_handlers('.*', [
            (r'/api/v2/fakes', FakeApi),
            (r'/api/v2/fakes/(?P<id>\d+)', FakeApi),
            (r'/api/v2/fakes/(?P<name>[\dA-Za-z]+)', FakeApi),
            (r'/api/v2/fakes/(?P<id>\d+)/(?P<name>[^/][\dA-Za-z]+)', FakeApi)
        ])

        # assert 'POST' method succeeds with an apiKey, and that our validator was called
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request(
                'POST', f'http://127.0.0.1:3458/api/v2/fakes',
                headers={
                    'Authorization': f'Bearer {TokenUtil.createToken(bearerTokenSecret, { 'api_access':True, 'can_edit':True }, AuthorizationMethod.BEARERTOKEN)}'
                },
                body=json.dumps({
                    'id': '1',
                    'name': 'test1'
                }))
            assert response.status == 204
        assert validatorCallCount == 1
        # assert 'PUT' method succeeds with an apiKey, and that our validator was called
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('PUT', f'http://127.0.0.1:3458/api/v2/fakes/2/test2', headers={
                'X-API-Key': TokenUtil.createToken(apiKeySecret, { 'api_access':True, 'can_edit':True }, AuthorizationMethod.APIKEY)
            })
            assert response.status == 204
        assert validatorCallCount == 2
        # assert 'GET' method does not require an apikey, and that our validator is not called
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('GET', f'http://127.0.0.1:3458/api/v2/fakes/1')
            assert response.status == 200
            data:bytes = await response.data
            assert data is not None
            assert data.decode() == 'test1'
        async with urllib3.AsyncPoolManager() as async_urllib3:
            response = await async_urllib3.request('GET', f'http://127.0.0.1:3458/api/v2/fakes/2')
            assert response.status == 200
            data:bytes = await response.data
            assert data is not None
            assert data.decode() == 'test2'
        assert validatorCallCount == 2
    finally:
        server.stop()
