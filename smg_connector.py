# --
# File: smg_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

import requests
import json
from bs4 import BeautifulSoup


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class SymantecMessagingGatewayConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(SymantecMessagingGatewayConnector, self).__init__()

        self._state = None
        self._token = None
        self._session = None
        self._base_url = None

    def initialize(self):

        config = self.get_config()

        self._state = self.load_state()
        self._session = requests.Session()
        self._base_url = "{0}/{1}".format(config['url'].strip('/'), 'brightmail')

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(self._session, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        url = self._base_url + endpoint

        try:
            r = request_func(
                            url,
                            data=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))), resp_json)

        if not r:
            return self._process_html_response(r, action_result)

        return RetVal(phantom.APP_SUCCESS, r)

    def _login(self, action_result):

        self.debug_print("Attempting login")

        ret_val, resp = self._make_rest_call('/viewLogin.do', action_result)

        if phantom.is_fail(ret_val):
            return ret_val

        soup = BeautifulSoup(resp.text, "html.parser")
        found_tag = soup.find('input', {'name': 'lastlogin'})
        if not found_tag:
            return action_result.set_status(phantom.APP_ERROR, "Could not find last login time in viewLogin response")
        lastlogin = found_tag['value']

        config = self.get_config()

        params = {
                'lastlogin': lastlogin,
                'username': config['username'],
                'password': config['password']
            }

        ret_val, resp = self._make_rest_call('/login.do', action_result, params=params)

        if phantom.is_fail(ret_val):
            return ret_val

        soup = BeautifulSoup(resp.text, "html.parser")
        found_tag = soup.find('input', {'name': 'symantec.brightmail.key.TOKEN'})
        if not found_tag:
            return action_result.set_status(phantom.APP_ERROR, "Could not find token in login response")
        self._token = found_tag['value']

        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        if phantom.is_fail(self._login(action_result)):
            self.save_progress("Login Failed")
            self.save_progress("Test Connectivity Failed")
            return action_result.get_status()

        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _blacklist_item(self, action_result, item, item_type):

        if phantom.is_fail(self._login(action_result)):
            self.debug_print("Login Failed")
            return action_result.get_status()

        ret_val, resp = self._make_rest_call('/reputation/sender-group/viewSenderGroup.do?view=badSenders', action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        if item_type == 'ip':
            sender_group = '1|1'
        else:
            sender_group = '1|3'

        params = {'symantec.brightmail.key.TOKEN': self._token, 'view': 'badSenders', 'selectedSenderGroups': sender_group}
        ret_val, resp = self._make_rest_call('/reputation/sender-group/viewSenderGroup.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        ret_val, resp = self._make_rest_call('/reputation/sender-group/addSender.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        params = {'symantec.brightmail.key.TOKEN': self._token, 'addEditSenders': item, 'view': 'badSenders'}
        ret_val, resp = self._make_rest_call('/reputation/sender-group/saveSender.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        params = {'symantec.brightmail.key.TOKEN': self._token, 'view': 'badSenders'}
        ret_val, resp = self._make_rest_call('/reputation/sender-group/saveGroup.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        return phantom.APP_SUCCESS

    def _unblacklist_item(self, action_result, item, item_type):

        if phantom.is_fail(self._login(action_result)):
            self.debug_print("Login Failed")
            return action_result.get_status()

        ret_val, resp = self._make_rest_call('/reputation/sender-group/viewSenderGroup.do?view=badSenders', action_result)
        if phantom.is_fail(ret_val):
            return ret_val

        if item_type == 'ip':
            sender_group = '1|1'
        else:
            sender_group = '1|3'

        params = {'symantec.brightmail.key.TOKEN': self._token, 'view': 'badSenders', 'selectedSenderGroups': sender_group}
        ret_val, resp = self._make_rest_call('/reputation/sender-group/viewSenderGroup.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        soup = BeautifulSoup(resp.text, "html.parser")
        member_table = soup.find('table', {'id': 'membersList'})
        if not member_table:
            return action_result.set_status(phantom.APP_ERROR, "Could not find member list table")

        member_tags = soup.findAll('tr')
        if not member_tags:
            return action_result.set_status(phantom.APP_ERROR, "Could not find any items in bad senders list")
        for tag in member_tags:
            if item in tag.text:
                checkbox = tag.find('input', {'name': 'selectedGroupMembers'})
                if not checkbox:
                    return action_result.set_status(phantom.APP_ERROR, "Could not find item ID")
                item_id = checkbox['value']

        ret_val, resp = self._make_rest_call('/reputation/sender-group/addSender.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        params = {'symantec.brightmail.key.TOKEN': self._token, 'selectedGroupMembers': item_id, 'view': 'badSenders', 'selectedSenderGroups': '1|3'}
        ret_val, resp = self._make_rest_call('/reputation/sender-group/deleteSender.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        params = {'symantec.brightmail.key.TOKEN': self._token, 'view': 'badSenders'}
        ret_val, resp = self._make_rest_call('/reputation/sender-group/saveGroup.do', action_result, params=params)
        if phantom.is_fail(ret_val):
            return ret_val

        return phantom.APP_SUCCESS

    def _handle_blacklist_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._blacklist_item(action_result, param['email'], 'email')
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully blacklisted email")

    def _handle_unblacklist_email(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._unblacklist_item(action_result, param['email'], 'email')
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully unblacklisted email")

    def _handle_blacklist_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._blacklist_item(action_result, param['domain'], 'domain')
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully blacklisted domain")

    def _handle_unblacklist_domain(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._unblacklist_item(action_result, param['domain'], 'domain')
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully unblacklisted domain")

    def _handle_blacklist_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._blacklist_item(action_result, param['ip'], 'ip')
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully blacklisted IP")

    def _handle_unblacklist_ip(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val = self._unblacklist_item(action_result, param['ip'], 'ip')
        if phantom.is_fail(ret_val):
            return ret_val

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully unblacklisted IP")

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'blacklist_email':
            ret_val = self._handle_blacklist_email(param)
        elif action_id == 'unblacklist_email':
            ret_val = self._handle_unblacklist_email(param)
        elif action_id == 'blacklist_domain':
            ret_val = self._handle_blacklist_domain(param)
        elif action_id == 'unblacklist_domain':
            ret_val = self._handle_unblacklist_domain(param)
        elif action_id == 'blacklist_ip':
            ret_val = self._handle_blacklist_ip(param)
        elif action_id == 'unblacklist_ip':
            ret_val = self._handle_unblacklist_ip(param)

        return ret_val


if __name__ == '__main__':

    # import pudb
    import argparse

    # pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = SymantecMessagingGatewayConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
