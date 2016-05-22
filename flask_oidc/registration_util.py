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

import argparse
import json
import os.path
import sys

from flask_oidc import discovery
from flask_oidc import registration


def _parse_args():
    parser = argparse.ArgumentParser(description='Help register an OpenID '
                                     'Client')
    parser.add_argument('provider_url',
                        help='Base URL to the provider to register at')
    parser.add_argument('application_url',
                        help='Base URL to the application')
    parser.add_argument('--token-introspection-uri',
                        help='Token introspection URI')
    parser.add_argument('--output-file', default='client_secrets.json',
                        help='File to write client info to')
    parser.add_argument('--debug', action='store_true')
    return parser.parse_args()


def main():
    args = _parse_args()
    if os.path.exists(args.output_file):
        print('Output file exists. Please provide other filename')
        return 1
    with open(args.output_file, 'w') as outfile:
        redirect_uris = ['%s/oidc_callback' % args.application_url]
        registration.check_redirect_uris(redirect_uris)
        try:
            OP = discovery.discover_OP_information(args.provider_url)
        except Exception as ex:
            print('Error discovering OP information')
            if args.debug:
                print(ex)
            return 1
        if args.debug:
            print('Provider info: %s' % OP)
        try:
            reg_info = registration.register_client(OP, redirect_uris)
        except Exception as ex:
            print('Error registering client')
            if args.debug:
                print(ex)
            return 1
        if args.debug:
            print('Registration info: %s' % reg_info)

        if args.token_introspection_uri:
            reg_info['web']['token_introspection_uri'] = \
                args.token_introspection_uri

        outfile.write(json.dumps(reg_info))
        print('Client information file written')


if __name__ == '__main__':
    retval = main()
    if retval:
        sys.exit(retval)
