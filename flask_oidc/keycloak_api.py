import logging
import json
import httplib2

from jose import jwt
from urllib.parse import urlencode

# KEYCLOAK URLS
URL_ISSUER = "{base_url}/realms/{realm-name}"
URL_WELL_KNOWN = "{base_url}/realms/{realm-name}/.well-known/openid-configuration"
URL_TOKEN = "{base_url}/realms/{realm-name}/protocol/openid-connect/token"
URL_USERINFO = "{base_url}/realms/{realm-name}/protocol/openid-connect/userinfo"
URL_LOGOUT = "{base_url}/realms/{realm-name}/protocol/openid-connect/logout"
URL_CERTS = "{base_url}/realms/{realm-name}/protocol/openid-connect/certs"
URL_INTROSPECT = "{base_url}/realms/{realm-name}/protocol/openid-connect/token/introspect"
URL_ENTITLEMENT = "{base_url}/realms/{realm-name}/authz/entitlement/{entitlement-endpoint}"
URL_PROTECTION = "{base_url}/realms/{realm-name}/authz/protection/{protection-endpoint}"
URL_AUTH = "{base_url}/realms/{realm-name}/protocol/openid-connect/auth"

logger = logging.getLogger(__name__)


class KeycloakAPI(object):

    def __init__(self):
        self.client_secrets = None
        logger.debug("Create a keycloak API object")

    def init_app(self, client_secrets):
        self.client_secrets = client_secrets

    def impersonate(self, token, subject, target_client):
        """
        :param token: Access token from the impersonator
        :param subject: the name of the target account
        :param target_client: the id of the target client
        :return: The access and refresh token for subject
        """
        if token is None:
            logger.error("The access token is not available.")
            return False
        headers = self._create_authorization_header(token)
        payload = self._create_impersonation_payload(token, subject, target_client)
        content, resp = self._execute_api_call(headers, payload)
        return self._process_api_response(content, resp)

    def _create_impersonation_payload(self, token, subject, target_client):
        return {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_id': self.client_secrets['client_id'],
                'client_secret': self.client_secrets['client_secret'],
                'requested_subject': subject,
                'requested_token_type': 'urn:ietf:params:oauth:token-type:refresh_token',
                'audience': target_client,
                'subject_token': token}

    def _execute_api_call(self, headers, payload):
        params_path = {"base_url": self.client_secrets["auth-server-url"], "realm-name": self.client_secrets["realm"]}
        resp, content = httplib2.Http().request(URL_TOKEN.format(**params_path), 'POST', headers=headers,
                                                body=urlencode(payload))
        return content, resp

    def authorize(self, token):
        """

        :param token: Access token
        :return: True if the user is authorized otherwise false
        """
        if token is None:
            logger.error("The access token is not available.")
            return False
        headers, payload = self._build_api_call_for_authorization(token)
        content, resp = self._execute_api_call(headers, payload)
        return self._process_api_response(content, resp)

    def _build_api_call_for_authorization(self, token):
        headers = self._create_authorization_header(token)
        payload = self._create_authorization_payload()
        return headers, payload

    def _create_authorization_header(self, token):
        return {'Authorization': 'Bearer ' + str(token),
                'Content-Type': 'application/x-www-form-urlencoded'}

    def _create_authorization_payload(self):
        return {'grant_type': 'urn:ietf:params:oauth:grant-type:uma-ticket',
                'audience': self.client_secrets['client_id']}

    def get_resource_info(self, resource_id):
        """
        Inquires the provider for a specific resource information
        :param resource_id: the id of the desired resource
        :type resource_id: str
        :return: a dictionary with the resource information
        """
        pat = self._get_protection_api_token()
        headers, payload = self._build_api_call_to_get_resource_info(pat["access_token"])
        content, resp = self._execute_get_resource_info_call(headers, payload, resource_id)
        return self._process_api_response(content, resp)

    def _process_api_response(self, content, resp):
        if resp.status != 200:
            logger.error("The call to keycloak endpoint was unsuccessful.")
            raise Exception(resp)
        if not isinstance(content, str):
            content = content.decode('utf-8')
        return json.loads(content)

    def _build_api_call_to_get_resource_info(self, token):
        headers = self._create_authorization_header(token)
        payload = {}
        return headers, payload

    def _execute_get_resource_info_call(self, headers, payload, resource_id):
        params_path = {"base_url": self.client_secrets["auth-server-url"], "realm-name": self.client_secrets["realm"],
                       "protection-endpoint": "resource_set/" + resource_id}
        resp, content = httplib2.Http().request(URL_PROTECTION.format(**params_path), 'GET', headers=headers,
                                                body=json.dumps(payload))
        return content, resp

    def jwt_decode(self, token):
        return jwt.decode(token, self.client_secrets["realm_pub_key"],
                          algorithms=self.client_secrets["token_algorithm"], audience=self.client_secrets['client_id'])

    def _get_protection_api_token(self):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'grant_type': 'client_credentials',
                   'client_id': self.client_secrets['client_id'], 'client_secret': self.client_secrets['client_secret']}
        content, resp = self._execute_api_call(headers, payload)
        return self._process_api_response(content, resp)
