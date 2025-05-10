# SPDX-FileCopyrightText: Copyright (C) Shaun Wilson
# SPDX-License-Identifier: MIT

import enum


class AuthorizationMethod(enum.StrEnum):
    """Identifies the security scheme used for Authorization."""
    APIKEY = 'apiKey'
    # TODO: BASICHTTP = 'basicHttp'
    BEARERTOKEN = 'bearerToken'
    # TODO: MUTUALTLS = 'mutualTLS'
    # TODO: OAUTH2 = 'oauth2'
    # TODO: OPENID = 'openId'
