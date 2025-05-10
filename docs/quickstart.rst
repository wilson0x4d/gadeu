Quick Start
============
.. _quickstart:

.. contents::

Installation
------------

You can install ``gadeu`` from `PyPI <https://pypi.org/project/gadeu/>`_ through usual means, such as ``pip``:

.. code:: bash

   pip install gadeu

Usage
-----

To use ``gadeu`` two things must be done; first you must register at least one authorization handler, and second you must apply one of the authorization decorators to a request handler method. Consider the following example:

.. code:: python

    import tornado
    from gadeu import *
    from .api.FakeApi import FakeApi

    # you configure an authorization handler
    AuthorizationManager.setAuthorizationHandler(
        AuthorizationMethod.APIKEY,
        handlers.ApiKeyAuthorizationHandler(key=apiKeySecret)
    )

    # you create a tornado app
    app = tornado.web.Application()
    # you add some handlers for your app
    app.add_handlers('.*', [
        (r'/api/v2/fakes', FakeApi),
        (r'/api/v2/fakes/(?P<id>\d+)', FakeApi),
        (r'/api/v2/fakes/(?P<name>[\dA-Za-z]+)', FakeApi),
        (r'/api/v2/fakes/(?P<id>\d+)/(?P<name>[^/][\dA-Za-z]+)', FakeApi)
    ])

Elsewhere in your project, you defined `FakeApi` and decorated at least one handler:

.. code:: python

    import tornado
    from gadeu import authorization

    class FakeApi(tornado.web.RequestHandler):    

        def initialize(self) -> None:
            pass

        @authorization.apiKey
        async def put(self, id:str, name:str) -> None:
            _d[id] = name
            self.set_status(204)


In the above example, ``FakeApi.put`` has been decorated with ``@authorization.apiKey`` which will force a check for a valid API Key. The expectations of that check are implemented via the ``ApiKeyAuthorizationHandler`` configured in the first few lines of the example. There are more options than are shown here, but this basic setup is enough for a server to check for a valid API Key.

If you need to generate an encryption key there is a ``TokenUtil`` class that exposes a ``createSecretKey(...)`` method which you can use for this purpose, example:

.. code:: python

    from gadeu import *

    # never share this key! it should get stored to a keyvault
    # and managed securely as part of your app settings.
    secretKey = TokenUtil.createSecretKey(AuthorizationMethod.APIKEY)

You can also use ``TokenUtil`` to generate API Keys using your secret key.

.. code:: python

    # share this key securely with your business partners, developers,
    # testers, etc that need to authorize requests with a server.
    apiKey = TokenUtil.createToken(secretKey, {'app':'bob123'}, AuthorizationMethod.APIKEY)

In the above example you can see a dictionary ``{'app':'bob123'}``, this is a "claims object" that gets encoded into the resulting token (``apiKey``).  Developers can access these claims via "validator functions" optionally set via the ``AuthorizationManager`` configured for the service.

Currently, only ``apiKey`` and ``bearerToken`` security schemes are supported, with a plan to add others as they are requested, PR'd, or required for our own projects. Both ``apiKey`` and ``bearerToken`` tokens are encrypted, and unless you leak your secret keys the wider public should not be able to peek at the token contents (ie. the "claims" you've stored.) That said, it is NOT a good practice to store anything sensitive in a claim (such as keys, passwords, etc.)

Custom/Proprietary Authorization Methods
----------------------------------------

You can subclass ``AuthorizationHandler`` to implement custom behavior. You are encouraged to submit a PR if you find yourself implementing any well known security schemes such as:

* mutualTLS
* OAuth2
* openIdConnect

Since we do not currently use these schemes there are not yet handlers for them, despite their popularity.

Checking Claims
---------------

In the future there will be decorators to facilitate claims assertions.

In the current implementation you can assert claims from a custom ``validator`` function, or even better check for claims within your handler methods. Example:

.. code:: python

    class FakeApi(tornado.web.RequestHandler):    

        @authorization.apiKey
        async def put(self, id:str, name:str) -> None:
            claims = self.request.arguments.get('claims', {})
            assert claims.get('can_edit', False)
            # do stuff

Obviously this is a naive example, and you should probably ``HTTPError`` back to the client, but you get the idea. If ``claims`` is an argument name you already use (and therefore would be clobbered by ``gadeu``) then you can configure a custom argument name in your ``AuthorizationHandler``. Example:

.. code:: python

    AuthorizationManager.setAuthorizationHandler(
        AuthorizationMethod.APIKEY,
        handlers.ApiKeyAuthorizationHandler(
            key=secretKey,
            claimsArgumentName='my_epic_arg_name')
    )
