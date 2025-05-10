# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT

from datetime import datetime, timezone
from gadeu import *
from uuid import uuid4
from punit import *

@fact
def supportsApiKeys() -> None:
    ts = datetime.now(timezone.utc)
    id = uuid4().hex
    key = TokenUtil.createSecretKey(AuthorizationMethod.APIKEY)
    expected = {
        'id': id,
        'ts': ts.isoformat()
    }
    token = TokenUtil.createToken(key, expected, AuthorizationMethod.APIKEY)
    actual = TokenUtil.getTokenClaims(key, token, AuthorizationMethod.APIKEY)
    assert collections.areSame(expected, actual)

@fact
def supportsBearerTokens() -> None:
    ts = datetime.now(timezone.utc)
    id = uuid4().hex
    key = TokenUtil.createSecretKey(AuthorizationMethod.BEARERTOKEN)
    expected = {
        'id': id,
        'ts': ts.isoformat()
    }
    token = TokenUtil.createToken(key, expected, AuthorizationMethod.BEARERTOKEN)
    actual = TokenUtil.getTokenClaims(key, token, AuthorizationMethod.BEARERTOKEN)
    assert collections.areSame(expected, actual)
