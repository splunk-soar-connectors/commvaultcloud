# File: commvaultcloud_connector.py
#
# Copyright (c) Commvault Systems, 2024
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.

import base64
import json
import re
from datetime import datetime, timedelta

# Phantom App imports
import phantom.app as phantom
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

# Usage of the consts file is recommended
import commvaultcloud_consts as Constants


# Usage of the consts file is recommended


class RetVal(tuple):

    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


def if_zero_set_none(value):
    """
    If the value is zero, return None
    """
    if value and int(value) > 0:
        return value
    return None


def extract_from_regex(
        message: str, default_value: str, *regex_string_args: str) -> str:
    """
    From the message, extract the strings matching the given patterns

    Args:
        message (str): The message from which to extract.
        default_value (str): The default value to return if no match is found.
        *regex_string_args (str): Variable number of regular expressions to match.

    Returns:
        str: The extracted string if a match is found, otherwise the default value.
    """
    for pattern in regex_string_args:
        matches = re.search(pattern, message, re.IGNORECASE)
        if matches and len(matches.groups()) > 0:
            return matches.group(1).strip()
    return default_value


def format_alert_description(msg: str) -> str:
    """
    Format alert description

    Args:
        msg (str): The message containing the alert description.

    Returns:
        str: The formatted alert description.
    """
    default_value = msg

    # Check if the message contains HTML tags
    if "<html>" in msg and "</html>" in msg:
        resp = msg[msg.find("<html>") + 6: msg.find("</html>")]
        msg = resp.strip()

        # Extract the alert message if it contains specific patterns
        if "Detected " in msg and " Please click " in msg:
            msg = msg[msg.find("Detected "): msg.find(" Please click ")]
            return msg
        if "Possible " in msg and "<span style=" in msg:
            msg = msg[msg.find("Possible "): msg.find("<span style=")]
            return msg
    return default_value


def field_mapper(field_name) -> str:
    """
    Map incoming fields

    Args:
        field_name (str): Query by field name.

    Returns:
        str: Return incoming field by field name.
    """
    field_map = {
        Constants.EVENT_TIME: "timeSource",
        Constants.EVENT_ID: "id",
        Constants.ORIGINATING_PROGRAM: "subsystem",
        Constants.ANOMALY_SUB_TYPE: "AnomalyType",
        Constants.JOB: "job",
        Constants.JOB_ID: "JobId",
        Constants.ORIGINATING_CLIENT: "client",
        Constants.AFFECTED_FILES_COUNT: "SuspiciousFileCount",
        Constants.MODIFIED_FILES_COUNT: "Modified",
        Constants.RENAMED_FILES_COUNT: "Renamed",
        Constants.CREATED_FILES_COUNT: "Created",
        Constants.DELETED_FILES_COUNT: "Deleted"
    }
    return field_map[field_name]



def get_unique_guid():
    """
    Generate a unique GUID.

    Returns:
        str: The unique GUID.
    """
    import random
    import string
    allowed_chars = string.ascii_uppercase + string.digits
    unique_id = ''.join(random.choice(allowed_chars) for i in range(6))
    return unique_id


class CommvaultCloudConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CommvaultCloudConnector, self).__init__()
        self._last_run_epoch = None
        self._current_run_epoch = None
        self._max_fetch = None
        self._state = None
        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._access_key = None
        self._original_access_key = None
        self._headers = list()
        self._phantom_api_token = None
        self.current_token_dict = dict()
        self.renew_token_validity_in_days = 1 * 365


    def _process_empty_response(self, response, action_result):
        """
        Process empty response

        Args:
            response: The HTTP response object.
        Returns:
            RetVal: The return value containing the status and data.
        """
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(
            action_result.set_status(
                phantom.APP_ERROR, "Empty response and no information in the header"
            ), None
        )

    def _process_html_response(self, response, action_result):
        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"
            return None
        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)
        message = message.replace(u'{', '{{').replace(u'}', '}}')
        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):
        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))
                ), None
            )

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace(u'{', '{{').replace(u'}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):
        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately
        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.status_code,
            r.text.replace('{', '{{').replace('}', '}}')
        )

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, data=None, method="get"):
        # **kwargs can be any additional parameters that requests.request accepts
        config = self.get_config()
        resp_json = None
        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(
                action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)),
                resp_json
            )

        # # Create a URL to connect to
        url = self._base_url + endpoint
        self.debug_print('Calling endpoint [{}]'.format(url))
        if data is not None:
            self.debug_print('Payload {}'.format(data))
        try:
            # Build headers with current access key
            request_headers = {
                "authtoken": self._access_key,
                "Content-Type": "application/json",
                "Accept": "application/json",
                'User-Agent': "SentinelDataConnector"
            }
            if headers and isinstance(headers, dict):
                request_headers.update(headers)
            r = request_func(
                url,
                # auth=(username, password),  # basic authentication
                data=data,
                headers=request_headers,
                verify=config.get('verify_server_cert', False)
            )
        except Exception as e:
            return RetVal(
                action_result.set_status(
                    phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))
                ), resp_json
            )
        # print('Return from rest {}'.format(self._process_response(r, action_result)))
        return self._process_response(r, action_result)


    def check_create_renew_token(self, param):
        """
        Checks if a valid access token is available. If not, it either creates a new token 
        or renews an expired token if it is still within the renewal period.
        Falls back to original token if new version features are not supported.
        """
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.debug_print("Checking for token validity")
        try:
            token_data = self._get_token_details()
            if not token_data:
                self.debug_print("Token details are not present. Attempting to create a new token")
                token_created = self._generate_access_token_v2(action_result)
                if token_created:
                    new_token = self._get_token_details(field_name='accessToken')
                    if new_token:
                        self._access_key = f"QSDK {str(new_token)}"
                        self.debug_print('New access token created successfully')
                    else:
                        self.debug_print('Token generation returned True but token not retrieved. Using original token.')
                        self._access_key = f"QSDK {self._original_access_key}"
                else:
                    self.debug_print('Token generation not supported by this server version. Using original token for backward compatibility.')
                    self._access_key = f"QSDK {self._original_access_key}"
            else:
                current_time = int(datetime.now().timestamp())
                token_expired = current_time >= int(token_data["accessTokenExpiry"])
                renewable_until = current_time < int(token_data["tokenRenewableTill"])
                if token_expired and renewable_until:
                    self.debug_print('Token has expired, attempting to refresh it')
                    token_renewed = self._renew_token(action_result, token_data['accessToken'], token_data['refreshToken'])
                    if token_renewed:
                        renewed_token = self._get_token_details(field_name='accessToken')
                        if renewed_token:
                            self._access_key = f"QSDK {str(renewed_token)}"
                            self.debug_print('Token renewed successfully')
                        else:
                            self.debug_print('Token renewal returned True but token not retrieved. Using original token.')
                            self._access_key = f"QSDK {self._original_access_key}"
                    else:
                        self.debug_print('Token renewal failed. Using original token for backward compatibility.')
                        self._access_key = f"QSDK {self._original_access_key}"
                elif not renewable_until:
                    self.debug_print('Token can not be renewed. Using original token for backward compatibility.')
                    self._access_key = f"QSDK {self._original_access_key}"
                else:
                    self.debug_print('Current access token is valid')
                    current_token = token_data.get('accessToken')
                    if current_token:
                        self._access_key = f"QSDK {str(current_token)}"
        except Exception as e:
            self.debug_print('Could not fetch access token due to [{}]. Using original token for backward compatibility.'.format(e))
            self._access_key = f"QSDK {self._original_access_key}"
            return True
        return True

    def _get_token_details(self, field_name=None):
        """
        Retrieves stored token details from the integration context.

        Args:
            field_name (str, optional): The specific field to retrieve. Defaults to None.

        Returns:
            dict or str: The full token details dictionary or a specific field value.
        """
        if 'tokenDetailsV2' in self._state:
            if field_name is not None:
                return self._state.get("tokenDetailsV2")[field_name]
            else:
                return self._state.get("tokenDetailsV2", {})
        else:
            return None

    def _update_token_details(self, new_access_token, new_refresh_token, token_expiry_timestamp,
                             renewable_until_timestamp):
        """
        Updates the stored token details in the integration context.

        Args:
            new_access_token (str): The new access token.
            new_refresh_token (str): The new refresh token.
            token_expiry_timestamp (int): The expiry timestamp of the access token.
            renewable_until_timestamp (int): The timestamp until which the token is renewable.
        """
        self._state.update({
            "tokenDetailsV2": {
                "accessToken": str(new_access_token),
                "refreshToken": str(new_refresh_token),
                "accessTokenExpiry": str(token_expiry_timestamp),
                "tokenRenewableTill": str(renewable_until_timestamp)
            }
        })
        self.debug_print('Token details are updated to {}'.format(self._state.get("tokenDetailsV2")))

    def _renew_token(self, action_result, access_token, refresh_token):
        """
        Renews the access token using the provided refresh token.

        Args:
            access_token (str): The expired access token.
            refresh_token (str): The refresh token used to generate a new access token.

        Returns:
            bool: True if the token was successfully renewed, False otherwise.
        """
        try:
            request_body = {
                "refreshToken": refresh_token,
                "accessToken": access_token,
            }
            
            ret_val, data = self._make_rest_call(
            "/v4/accesstoken/renew", action_result, data=json.dumps(request_body), method='post')

            # Check for errors
            if "errorCode" in data and data["errorCode"]:
                self.debug_print(f"Error {data['errorCode']}: {data.get('errorMessage', 'No error message provided')}")
                return False
            if 'tokenInfo' in data:
                data = data['tokenInfo']
            access_token = data.get("accessToken")
            refresh_token = data.get("refreshToken")
            token_expiry_timestamp = data.get("tokenExpiryTimestamp")
            renewable_until_timestamp = data.get("renewableUntilTimestamp")
            self._update_token_details(access_token, refresh_token, token_expiry_timestamp,
                                      renewable_until_timestamp)
            self.debug_print('Token has been rotated successfully')
            
        except Exception as error:
            return False
        return True

    def _generate_access_token_v2(self, action_result) -> bool:
        """
        Generates a new access token using the API token.

        Args:
            api_token (str): The API token used for authentication.

        Returns:
            bool: True if the token was successfully created, False otherwise.
        """
        new_access_token = None
        current_epoch = int(datetime.now().timestamp())
        token_expiry_epoch = (
                current_epoch + self.renew_token_validity_in_days * 24 * 60 * 60
        )
        token_name = f"splunk-token-renew-till-{token_expiry_epoch}"
        request_body = {
            "renewableUntilTimestamp": token_expiry_epoch,
            "tokenName": token_name,
        }
        try:
            ret_val, data = self._make_rest_call(
            "/v4/accesstoken", action_result, data=json.dumps(request_body), method='post')
            self.debug_print(data)
            if "errorCode" in data and data["errorCode"]:
                self.debug_print(f"Error {data['errorCode']}: {data.get('errorMessage', 'No error message provided')}")
                return False
            if 'tokenInfo' in data:
                data = data['tokenInfo']
            access_token = data.get("accessToken")
            refresh_token = data.get("refreshToken")
            token_expiry_timestamp = data.get("tokenExpiryTimestamp")
            renewable_until_timestamp = data.get("renewableUntilTimestamp")

            self._update_token_details(access_token, refresh_token, token_expiry_timestamp,
                                      renewable_until_timestamp)
        except Exception as error:
            self.debug_print(f"Could not generate access token [{error}]")
            return False
        return True

    def get_events(
            self,
            action_result,
            show_minor="false",
            show_major="true",
            show_critical="true"
    ):
        """
        Get events

        Args:
            action_result: The action result object.
            fromtime: The starting time for events.
            show_minor (str): Whether to show minor events. Default is "false".
            show_major (str): Whether to show major events. Default is "true".
            show_critical (str): Whether to show critical events. Default is "true".

        Returns:
            list: List of events if available, otherwise None.
        """
        # print('Entered get_events()')
        event_url = (
            f"/events?level=10&showInfo=false&showMinor={show_minor}&"
            f"showMajor={show_major}&showCritical={show_critical}"
        )
        current_date = datetime.utcnow()
        # print('Current date [{}]'.format(current_date))
        epoch = datetime(1970, 1, 1)
        current_epoch = int((current_date - epoch).total_seconds())
        self._current_run_epoch = current_epoch
        event_endpoint = f"{event_url}&fromTime={self._last_run_epoch}&toTime={self._current_run_epoch}"
        headers = {"pagingInfo": "0,10000"}
        ret_val, response = self._make_rest_call(
            event_endpoint, action_result, headers=headers, method='get'
        )
        if response and response.get("commservEvents"):
            return response.get("commservEvents")
        return None

    def get_events_list(self, action_result):
        """
        Function to get events

        Args:
            action_result: The action result object.

        Returns:
            list: List of events.
        """
        events = []
        critical_events = self.get_events(action_result, show_critical="true")
        major_events = self.get_events(action_result, show_major="true")
        if critical_events is not None:
            events.extend(critical_events)
        if major_events is not None:
            events.extend(major_events)
        return events

    def get_incident_details_v2(self, event: dict):
        """
        Parse incident details directly from an event object.
        This method does not make any additional REST/API calls.

        Args:
            event (dict): Event object from /events endpoint.

        Returns:
            dict: Dictionary containing incident details or None.
        """
        if not event or not isinstance(event, dict):
            return None

        message = event.get(Constants.DESCRIPTION, "")
        if not message:
            return None

        event_code = event.get("eventCodeString", "")
        event_code_to_type = getattr(Constants, "EVENT_CODE_TO_ANOMALY_TYPE", {})
        event_code_to_severity = getattr(Constants, "EVENT_CODE_TO_SEVERITY", {})
        anomaly_sub_type = event_code_to_type.get(event_code)
        if not anomaly_sub_type:
            return None
        
        severity = event_code_to_severity.get(event_code, Constants.SEVERITY_MEDIUM)

        job_id = extract_from_regex(
            message,
            "",
            rf"{field_mapper(Constants.JOB)} \[(.*?)\]",
        )
        if not job_id:
            job_id = extract_from_regex(
                message,
                "",
                rf"{field_mapper(Constants.JOB_ID)}:\[(.*?)\]",
            )

        description = format_alert_description(message)
        originating_client = extract_from_regex(
            message,
            "",
            r"ClientName:\[(.*?)\]",
            r"{} \[(.*?)\]".format(field_mapper(Constants.ORIGINATING_CLIENT)),
            r"{}:\[(.*?)\]".format(field_mapper(Constants.ORIGINATING_CLIENT)),
        )
        if not originating_client:
            client_entity = event.get("clientEntity", {})
            originating_client = client_entity.get("displayName") or client_entity.get("clientName") or ""

        details = {
            "files_list": [],
            "scanned_folder_list": [],
            "anomaly_sub_type": anomaly_sub_type,
            "severity": severity,
            "originating_client": originating_client,
            "affected_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}:\[(.*?)\]".format(field_mapper(Constants.AFFECTED_FILES_COUNT)),
                )
            ),
            "modified_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(field_mapper(Constants.MODIFIED_FILES_COUNT)),
                )
            ),
            "deleted_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(field_mapper(Constants.DELETED_FILES_COUNT)),
                )
            ),
            "renamed_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(field_mapper(Constants.RENAMED_FILES_COUNT)),
                )
            ),
            "created_files_count": if_zero_set_none(
                extract_from_regex(
                    message,
                    None,
                    r"{}FileCount:\[(.*?)\]".format(field_mapper(Constants.CREATED_FILES_COUNT)),
                )
            ),
            "job_start_time": None,
            "job_end_time": None,
            "job_id": job_id,
            "external_link": extract_from_regex(
                message, "", "href='(.*?)'", 'href="(.*?)"'
            ),
            "description": description,
        }
        return details

    def get_client_id(self, action_result, client_name):
        """
        Get client id from the client name

        Args:
            action_result: The action result object.
            client_name: The client name.

        Returns:
            int: The client ID.
        """
        client_id = None
        if client_name is not None:
            ret_val, resp = self._make_rest_call(
                "/GetId?clientname=" + client_name, action_result, method='get'
            )
            client_id = resp.get("clientId")
            if client_id < 0:
                client_id = 0
        return client_id

    def get_company_details(self, action_result):
        company_id = None
        try:
            ret_val, resp = self._make_rest_call("/V2/whoami", action_result, method='get'
                                                 )
            if 'company' in resp:
                company_id = resp.get('company').get('id')
        except Exception as e:
            self.debug_print('Could not find the company details due to [{}]'.format(e))
        return company_id

    def register(self, param):
        try:
            action_result = self.add_action_result(ActionResult(dict(param)))
            company_id = self.get_company_details(action_result)

            if company_id is not None:
                self.debug_print('Found company [{}]'.format(company_id))
                url = "/V4/Company/{}/SecurityPartners/Register/{}".format(company_id,
                                                                           Constants.PARTNER_ID)
                ret_val, resp = self._make_rest_call(
                    url, action_result, method='put'
                )
                self.debug_print('Response from registration [{}]'.format(resp))
                if 'error' in resp:
                    if resp['error']['errorCode'] == 0:
                        self.debug_print('Registered successfully!')
        except Exception as e:
            self.debug_print('Could not register due to [{}]'.format(e))
            pass

    def _fetch_incidents(
            self, action_result, max_fetch=100):
        """
        Fetch incidents

        Args:
            action_result: The action result object.

        Returns:
            list: List of incidents.
        """
        if self._max_fetch is not None:
            max_fetch = self._max_fetch
        events = self.get_events_list(action_result)
        out = []
        if not len(events) > 0:
            self.debug_print("There are no events")
            return events
        domain = 'Dummy Domain'
        events = sorted(events, key=lambda d: d.get("timeSource"))
        filtered_event_codes = {}
        self.debug_print('Total events fetched [{}]'.format(len(events)))
        for event in events:
            event_code = event.get("eventCodeString")
            if event_code not in Constants.SUPPORTED_EVENT_CODES:
                filtered_event_codes[event_code] = filtered_event_codes.get(event_code, 0) + 1
                continue
            event_id = event[
                field_mapper(Constants.EVENT_ID)
            ]
            event_time = event[
                field_mapper(Constants.EVENT_TIME)
            ]
            incident = {
                "facility": Constants.FACILITY,
                "msg": None,
                "msg_id": None,
                "process_id": None,
                "sd": {},
                "host_name": domain,
                "timestamp": datetime.utcnow().strftime(
                    "%Y-%m-%d %H:%M:%S"),
                "occurred": None,
                "event_id": event_id,
                "event_time": datetime.fromtimestamp(event_time).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "originating_program": event[
                    field_mapper(
                        Constants.ORIGINATING_PROGRAM
                    )
                ],
            }
            det = self.get_incident_details_v2(event)
            if not det:
                self.debug_print('Skipping event [{}] as incident details could not be extracted'.format(event_id))
                continue
            if det.get(Constants.ANOMALY_SUB_TYPE):
                incident.update(det)
                incident['msg'] = incident.get(Constants.DESCRIPTION)
                out.append(incident)
                if len(out) == max_fetch:
                    break
            

        if filtered_event_codes:
            self.debug_print('Filtered unsupported event codes [{}]'.format(filtered_event_codes))
        return out

    def _get_error_message_from_exception(self, e):
        """
        Get appropriate error message from the exception.

        Args:
            e: Exception object

        Returns:
            str: Error message.
        """
        error_code = None
        error_msg = Constants.ERR_MSG_UNAVAILABLE

        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except Exception:
            return error_code
        if not error_code:
            error_text = "Error Message: {}".format(error_msg)
        else:
            error_text = "Error Code: {}. Error Message: {}".format(error_code, error_msg)

        return error_text

    def _add_container(self, event):
        """
        Add container

        Args:
            event: The event data.

        Returns:
            str: Container ID if successful, otherwise False.
        """
        headers = {
            "ph-auth-token": self._phantom_api_token
        }
        container_id = None
        url = "{0}rest/container".format(self.get_phantom_base_url())
        container_common = {
            "description": event[Constants.DESCRIPTION],
        }
        date_obj = datetime.now()
        date_str = date_obj.strftime("%d %B, %Y, %H:%M:%S")
        post_data = container_common.copy()
        anomaly_type = event.get(Constants.ANOMALY_SUB_TYPE, 'Unknown Threat')
        post_data['name'] = '{} at {}'.format(anomaly_type, date_str)
        post_data['source_data_identifier'] = '{}_{}'.format(event[Constants.EVENT_ID], get_unique_guid())
        post_data['label'] = Constants.CONTAINER_LABEL
        post_data['sensitivity'] = Constants.SENSITIVITY_AMBER
        post_data['severity'] = (event[Constants.SEVERITY] or Constants.SEVERITY_MEDIUM).lower()
        post_data['status'] = Constants.CONTAINER_STATUS_OPEN
        json_blob = json.dumps(post_data)
        response = requests.post(url, data=json_blob, headers=headers, verify=False)
        # print(response)
        if response is None or response.status_code != 200:
            if response is None:
                self.debug_print('Could not create container/event.')
            else:
                self.debug_print('error {} {}'.format(response.status_code, json.loads(response.text)['message']))
            return False
        container_id = response.json().get('id')
        self.debug_print('Events with container id [{}] got created successfully'.format(container_id))
        return container_id

    def _add_artifact(self, container_id, event):
        """
        Add artifact

        Args:
            container_id: The container ID.
            event: The event data.

        Returns:
            bool: True if successful, otherwise False.
        """
        headers = {
            "ph-auth-token": self._phantom_api_token
        }
        artifact_id = get_unique_guid()
        url = '{}rest/artifact'.format(self.get_phantom_base_url())
        post_data = dict()
        post_data['name'] = 'artifact for {}'.format(Constants.FACILITY)
        post_data['label'] = Constants.CONTAINER_LABEL
        post_data['container_id'] = container_id
        post_data['source_data_identifier'] = artifact_id

        raw_description = event.get(Constants.DESCRIPTION, '')
        clean_description = BeautifulSoup(raw_description, "html.parser").get_text(" ", strip=True)

        cef = {
            'deviceHostname': event[Constants.ORIGINATING_CLIENT],
            'deviceFacility': event['facility'],
            'fileName': event['files_list'],
            'destinationProcessName': event[Constants.ORIGINATING_PROGRAM],
            'src': event[Constants.ANOMALY_SUB_TYPE],
            'severity': event.get(Constants.SEVERITY, Constants.SEVERITY_MEDIUM),
            'message': clean_description,
            'eventId': event.get('event_id', ''),
            'eventTime': event.get('event_time', '')
        }
        data = cef.copy()
        data[Constants.AFFECTED_FILES_COUNT] = event.get(Constants.AFFECTED_FILES_COUNT)
        data[Constants.MODIFIED_FILES_COUNT] = event.get(Constants.MODIFIED_FILES_COUNT)
        data[Constants.DELETED_FILES_COUNT] = event.get(Constants.DELETED_FILES_COUNT)
        data[Constants.RENAMED_FILES_COUNT] = event.get(Constants.RENAMED_FILES_COUNT)
        data[Constants.CREATED_FILES_COUNT] = event.get(Constants.CREATED_FILES_COUNT)
        post_data['cef'] = cef
        post_data['data'] = data
        json_blob = json.dumps(post_data)
        r = requests.post(url, data=json_blob, headers=headers, verify=False)
        if r is None or r.status_code != 200:
            if r is None:
                self.debug_print('Could not update artifact')
            else:
                error_msg = json.loads(r.text)
                self.debug_print('error {} {}'.format(r.status_code, error_msg['message']))
            return False
        resp_data = r.json()
        if 'id' not in resp_data:
            return False
        else:
            self.debug_print('Artifact is added.')
        return True

    def _handle_disable_user(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        user_id = None
        try:
            user_email = param['user_email']
            # response = self.http_request("GET", "/User?level=10")
            ret_val, response = self._make_rest_call(
                "/User?level=10", action_result, method="get"
            )
            user_list = response["users"]
            current_user = next(
                (
                    user
                    for user in user_list
                    if user.get("email") == user_email or user.get("UPN") == user_email
                ),
                None,
            )
            if current_user:
                user_id = str(current_user.get("userEntity", {}).get("userId"))
                # response = self.http_request("GET", f"/User/{user_id}")
                ret_val, response = self._make_rest_call(
                    f"/User/{user_id}", action_result, method="get"
                )
                if ret_val:
                    if response.get("users", [{}])[0].get("enableUser"):
                        # response = self.http_request("PUT", f"/User/{user_id}/Disable")
                        ret_val, response = self._make_rest_call(
                            f"/User/{user_id}/Disable", action_result, method="put"
                        )
                        if phantom.is_fail(ret_val):
                            return action_result.get_status()

                        else:
                            if response.get("response", [{}])[0].get("errorCode") > 0:
                                error_msg = "Failed to disable user"
                                raise Exception(error_msg)
                            else:
                                action_result.add_data(response)
                    else:
                        self.save_progress("User [{}] is already disabled.".format(user_email))
            else:
                raise Exception("Could not find user with email [{}]".format(user_email))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error while disabling user: {}".format(error_message)
            )
        self.save_progress('User {} is disabled'.format(user_email))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call(
            '/events?level=1', action_result
        )
        self.debug_print('ret_val returned [{}]'.format(ret_val))
        if phantom.is_fail(ret_val):
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_on_poll(self, param):
        events = list()
        self.save_progress(
            "In action handler for: {0}".format(self.get_action_identifier())
        )
        self._max_fetch = param.get("container_count", "")
        action_result = self.add_action_result(ActionResult(dict(param)))
        last_run = self._state.get("last_run")
        #last_run = None
        if last_run is None:
            self.debug_print("Run Mode: First Scheduled Poll")
            back_fill = datetime.utcnow().astimezone() - timedelta(days=30)
            self._last_run_epoch = int(back_fill.timestamp())
        else:
            self.debug_print("Run Mode: Scheduled Poll")
            self._last_run_epoch = last_run
            self.debug_print('Got last run as [{}] from state'.format(self._last_run_epoch))
        self.debug_print('Last run state [{}]'.format(self._last_run_epoch))
        if self.is_poll_now():
            self.debug_print("Run Mode: Poll Now")
        try:
            events = self._fetch_anomalous_events(param)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error retrieving events during poll: {}".format(error_message)
            )

        self.debug_print(f"Total events retrieved {len(events)}")
        self.save_progress(f"Total events retrieved {len(events)}")
        self.debug_print(f"Total events retrieved {len(events)}")
        try:
            self._create_container_and_artifact(events)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, error_message)
        self.save_progress("Polling complete")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_container_and_artifact(self, events):
        """
        Create container and artifact for each event in the list.

        Args:
            events: List of events.
        """
        for event in events:
            # self.debug_print('Processing event [{}]'.format(event))
            container_id = self._add_container(event)
            if container_id is not None:
                if self._add_artifact(container_id, event):
                    self.debug_print('Container and artifact is added')

    def _fetch_anomalous_events(self, param):
        """
        Fetch anomalous events.

        Args:
            param: The parameters.

        Returns:
            list: List of events.
        """
        events = None
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        events = self._fetch_incidents(action_result)
        self.debug_print('Number of filtered events are [{}]'.format(len(events)))
        return events

    def _handle_disable_data_aging(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        error_msg = None
        try:
            client_name = param.get('client_name', '')
            client_id = self.get_client_id(action_result, client_name)
            if int(client_id) != 0:
                body = {
                    "clientProperties": {
                        "Client": {"ClientEntity": {"clientId": int(client_id)}},
                        "clientProps": {
                            "clientActivityControl": {
                                "activityControlOptions": [
                                    {
                                        "activityType": 16,
                                        "enableActivityType": False,
                                        "enableAfterADelay": False,
                                    }
                                ]
                            }
                        },
                    }
                }
                # print(body)
                ret_val, response = self._make_rest_call(
                    "/Client/" + str(client_id), action_result, data=json.dumps(body), method="post"
                )
                # print('Response from data aging API {}'.format(response))
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                action_result.add_data(response)
                summary = action_result.update_summary({})
                if "errorCode" in response and int(response.get("errorCode")) != 0:
                    if response.get("errorMessage"):
                        error_msg = response.get("errorMessage")
                        raise Exception(error_msg)
                    summary['status'] = 'Data aging is disabled for client [{}]'.format(client_name)
            else:
                raise Exception('Invalid client [{}]'.format(client_name))
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error while disabling data aging: {}".format(error_message)
            )
        self.save_progress('Data aging is disabled for client [{}]'.format(client_name))
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_disable_idp(self, param):
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))
        error_msg = None
        not_enable = False
        try:
            provider_name = param.get('provider_name', '')
            ret_val, response = self._make_rest_call(
                "/V4/SAML/{}".format(provider_name), action_result, method="get"
            )
            if "error" in response:
                raise Exception(response.get('error', {}).get('errorString', ''))
            if response.get("enabled"):
                self.save_progress(f"SAML is enabled for identity server [{provider_name}]. Going to disable it")
                body = {"enabled": not_enable, "type": "SAML"}
                ret_val, response = self._make_rest_call(
                    "/V4/SAML/{}".format(provider_name), action_result, data=body, method="put"
                )
                if phantom.is_fail(ret_val):
                    return action_result.get_status()
                action_result.add_data(response)
                if response.get("errorCode"):
                    error_msg = response.get("errorCode")
                    raise Exception(error_msg)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(
                phantom.APP_ERROR, "Error while disabling provider: {}".format(error_message)
            )
        self.save_progress('Provider {} is disabled'.format(provider_name))
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        ret_val = phantom.APP_SUCCESS
        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()
        self.check_create_renew_token(param)
        self.register(param)
        self.debug_print("action_id", self.get_action_identifier())
        if action_id == 'disable_user':
            ret_val = self._handle_disable_user(param)

        if action_id == 'on_poll':
            ret_val = self._handle_on_poll(param)

        if action_id == 'disable_data_aging':
            ret_val = self._handle_disable_data_aging(param)

        if action_id == 'disable_idp':
            ret_val = self._handle_disable_idp(param)

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        return ret_val

    def initialize(self):
        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()
        # get the asset config
        config = self.get_config()
        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """
        base_url = config.get('CommvaultEndpoint').strip().rstrip('/')
        if not base_url.lower().endswith('/api'):
            base_url = '{}/api'.format(base_url)
        self._base_url = base_url
        self._access_key = config.get('CommvaultAccessToken').strip()
        self._original_access_key = self._access_key
        self._phantom_api_token = config.get('PhantomAPIToken').strip()
        self._headers = {
            "authtoken": 'QSDK {}'.format(self._access_key),
            "Content-Type": "application/json",
            "Accept": "application/json",
            'User-Agent': "SentinelDataConnector"
        }
        self.debug_print('Headers [{}]'.format(self._headers))
        return phantom.APP_SUCCESS

    def finalize(self):
        # Save the state, this data is saved across actions and app upgrades
        self._state["last_run"] = self._current_run_epoch
        self.save_state(self._state)
        return phantom.APP_SUCCESS


def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)
    argparser.add_argument(
        "-v",
        "--verify",
        action="store_true",
        help="verify",
        required=False,
        default=False,
    )

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = CommvaultCloudConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=verify)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=verify, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CommvaultCloudConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)


if __name__ == '__main__':
    main()
