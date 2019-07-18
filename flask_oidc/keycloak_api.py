import logging
import json
import httplib2

from jose import jwt
from six.moves.urllib.parse import urlencode
from PlanOne.keycloak_oidc.urls_patterns import URL_TOKEN, URL_PROTECTION

logger = logging.getLogger(__name__)


class KeycloakAPI(object):
    client_secrets = None

    def __init__(self):
        logger.debug("Create a keycloak API object")

    def init_app(self, client_secrets):
        self.client_secrets = client_secrets

    def impersonate(self, token, subject, target_client):
        if token is None:
            logger.error("The access token is not available.")
            return False
        headers = self._create_authorization_header(token)
        payload = self._create_impersonation_payload(token, subject, target_client)
        try:
            content, resp = self._execute_impersonation_call(headers, payload)
            return self._process_api_response(content, resp)
        except Exception as e:
            logger.error(str(e))

    def _create_impersonation_payload(self, token, subject, target_client):
        return {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_id': self.client_secrets['client_id'],
                'client_secret': self.client_secrets['client_secret'],
                'requested_subject': subject,
                'requested_token_type': 'urn:ietf:params:oauth:token-type:refresh_token',
                'audience': target_client,
                'subject_token': token}

    def _execute_impersonation_call(self, headers, payload):
        params_path = {"base_url": self.client_secrets["base_url"], "realm-name": self.client_secrets["realm"]}
        resp, content = httplib2.Http().request(URL_TOKEN.format(**params_path), 'POST', headers=headers,
                                                body=urlencode(payload))
        return content, resp

    def authorize(self, token):
        if token is None:
            logger.error("The access token is not available.")
            return False
        headers, payload = self._build_api_call_for_authorization(token)
        try:
            content, resp = self._execute_authorization_call(headers, payload)
            return self._process_api_response(content, resp)
        except Exception as e:
            logger.error(str(e))

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

    def _execute_authorization_call(self, headers, payload):
        params_path = {"auth-server-url": self.client_secrets["auth-server-url"], "realm": self.client_secrets["realm"]}
        resp, content = httplib2.Http().request(URL_TOKEN.format(**params_path), 'POST', headers=headers,
                                                body=urlencode(payload))
        return content, resp

    def get_resource_info(self, token, resource_id):
        """
        Inquires the provider for a specific resource information
        :param token: the access token to authenticate the access
        :type token: str
        :param resource_id: the id of the desired resource
        :type resource_id: str
        :return: a dictionary with the resource information
        """
        if token is None:
            logger.error("The access token is not available.")
            return None
        headers, payload = self._build_api_call_to_get_resource_info(token)
        try:
            content, resp = self._execute_get_resource_info_call(headers, payload, resource_id)
            return self._process_api_response(content, resp)
        except Exception as e:
            logger.error(str(e))
        logger.error("No information about the resource was found.")
        return None

    def _process_api_response(self, content, resp):
        if resp.status != 200:
            logger.error("The call to keycloak endpoint was unsuccessful.")
            raise Exception(resp)
        if not isinstance(content, str):
            content = content.decode('utf-8')
        return json.loads(content)

    def _build_api_call_to_get_resource_info(self, token):
        headers = self._create_get_resource_info_header(token)
        payload = {}
        return headers, payload

    def _create_get_resource_info_header(self, token):
        return {'Authorization': 'Bearer ' + str(token)}

    def _execute_get_resource_info_call(self, headers, payload, resource_id):
        params_path = {"auth-server-url": self.client_secrets["auth-server-url"], "realm": self.client_secrets["realm"],
                       "protection-endpoint": "resource_set/" + resource_id}
        resp, content = httplib2.Http().request(URL_PROTECTION.format(**params_path), 'GET', headers=headers,
                                                body=json.dumps(payload))
        return content, resp

    def jwt_decode(self, token):
        return jwt.decode(token, self.client_secrets["realm_pub_key"],
                          algorithms=self.client_secrets["token_algorithm"], audience=self.client_secrets['client_id'])
