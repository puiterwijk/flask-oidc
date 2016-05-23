# Copyright (c) 2016, Patrick Uiterwijk <patrick@puiterwijk.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import json
import httplib2


def check_redirect_uris(uris, client_type=None):
    """
    This function checks all return uris provided and tries to deduce
    as what type of client we should register.

    :param uris: The redirect URIs to check.
    :type uris: list
    :param client_type: An indicator of which client type you are expecting
        to be used. If this does not match the deduced type, an error will
        be raised.
    :type client_type: str
    :returns: The deduced client type.
    :rtype: str
    :raises ValueError: An error occured while checking the redirect uris.

    .. versionadded:: 1.0
    """
    if client_type not in [None, 'native', 'web']:
        raise ValueError('Invalid client type indicator used')

    if not isinstance(uris, list):
        raise ValueError('uris needs to be a list of strings')

    if len(uris) < 1:
        raise ValueError('At least one return URI needs to be provided')

    for uri in uris:
        if uri.startswith('https://'):
            if client_type == 'native':
                raise ValueError('https url with native client')
            client_type = 'web'
        elif uri.startswith('http://localhost'):
            if client_type == 'web':
                raise ValueError('http://localhost url with web client')
            client_type = 'native'
        else:
            raise ValueError('Invalid uri provided: %s' % uri)

    return client_type


class RegistrationError(Exception):
    """
    This class is used to pass errors reported by the OpenID Provider during
    dynamic registration.

    .. versionadded:: 1.0
    """
    errorcode = None
    errordescription = None

    def __init__(self, response):
        self.errorcode = response['error']
        self.errordescription = response.get('error_description')


# OpenID Connect Dynamic Client Registration 1.0
def register_client(provider_info, redirect_uris):
    """
    This function registers a new client with the specified OpenID Provider,
    and then returns the regitered client ID and other information.

    :param provider_info: The contents of the discovery endpoint as
        specified by the OpenID Connect Discovery 1.0 specifications.
    :type provider_info: dict
    :param redirect_uris: The redirect URIs the application wants to
        register.
    :type redirect_uris: list
    :returns: An object containing the information needed to configure the
        actual client code to communicate with the OpenID Provider.
    :rtype: dict
    :raises ValueError: The same error as used by check_redirect_uris.
    :raises RegistrationError: Indicates an error was returned by the OpenID
        Provider during registration.

    .. versionadded:: 1.0
    """
    client_type = check_redirect_uris(redirect_uris)

    submit_info = {'redirect_uris': redirect_uris,
                   'application_type': client_type,
                   'token_endpoint_auth_method': 'client_secret_post'}

    headers = {'Content-type': 'application/json'}

    _, content = httplib2.Http().request(
        provider_info['registration_endpoint'], 'POST',
        json.dumps(submit_info), headers=headers)

    client_info = json.loads(content)

    if 'error' in client_info:
        raise Exception('Error occured during registration: %s (%s)'
                        % (client_info['error'],
                           client_info.get('error_description')))

    json_file = {'web': {
        'client_id': client_info['client_id'],
        'client_secret': client_info['client_secret'],
        'auth_uri': provider_info['authorization_endpoint'],
        'token_uri': provider_info['token_endpoint'],
        'userinfo_uri': provider_info['userinfo_endpoint'],
        'redirect_uris': redirect_uris,
        'issuer': provider_info['issuer'],
    }}

    return json_file
