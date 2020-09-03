"""
Support for ExperiaBox V10A
"""
import base64
import hashlib
import logging
import os
import re
from collections import namedtuple
from datetime import datetime, timezone

import requests
import voluptuous as vol

import homeassistant.helpers.config_validation as cv
import homeassistant.util.dt as dt_util
from homeassistant.components.device_tracker import (
    DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, CONF_SSL, CONF_SCAN_INTERVAL

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
})

def get_scanner(hass, config):
    """Validate the configuration and return an ExperiaBox V10A device scanner."""
    try:
        return ExperiaBoxV10ADeviceScanner(config[DOMAIN])
    except ConnectionError:
        return None

Device = namedtuple('Device', ['mac', 'name', 'ip', 'last_update'])

class ExperiaBoxV10ADeviceScanner(DeviceScanner):
    """This class queries an Experia Box V10A."""

    def __init__(self, config):
        """Initialize the scanner."""
        host = config[CONF_HOST]
        username, password = config[CONF_USERNAME], config[CONF_PASSWORD]
        ssl = True

        self.ca_cert_bundle = os.path.join(os.path.dirname(__file__), 'ca-bundle-kpn-pkio-g3-server.pem')

        self.parse_macs = re.compile('[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}')

        self.base_url = 'http{}://{}'.format('s' if ssl else '', host)

        self.username = hashlib.sha512(hashlib.md5(username.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()

        self.password = hashlib.sha512(hashlib.md5(password.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest()

        self.last_results = []
        self.success_init = self._update_info()

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return [device.mac for device in self.last_results]

    def get_device_name(self, device):
        """Return the name of the given device or None if we don't know."""
        filter_named = [result.name for result in self.last_results
                        if result.mac == device]

        if filter_named:
            return filter_named[0]
        return None

    def get_extra_attributes(self, device):
        """Return the extra attibutes of the given device."""
        filter_device = next((
            result for result in self.last_results
            if result.mac == device), None)
        return {'ip': filter_device.ip}

    def _update_info(self):
        """Ensure the information from the ExperiaBox V10A is up to date.
        Return boolean if scanning successful.
        """

        _LOGGER.info("Loading devices...")

        # We need to store a cookie
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})

        ts = round(datetime.now(timezone.utc).timestamp() * 1000)

        # Retrieve login.htm first, to retrieve the "httoken" to do the actual POST /login.cgi
        login_url_initial = '{}/login.htm'.format(self.base_url)
        page_initial = session.get(login_url_initial, timeout = 10, verify = self.ca_cert_bundle)

        # Security by obfuscation
        # The token is "hidden" as a base64 string, and is in the page source as a img with base64 data
        # the base64 portion that contains the token is appended after "yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"
        httoken_search = re.search("yH5BAEAAAAALAAAAAABAAEAAAIBRAA7(.+)\" border=0>", page_initial.text)

        authenticity_token = base64.b64decode(httoken_search.group(1)).decode('utf-8')

        # construct the login payload. the values usr and pws are MD5'd and then the MD5 hash is SHA512'd
        # no salt
        login_payload = {
            "httoken": authenticity_token,
            "usr": self.username,
            "pws": self.password
        }

        login_url = '{}/login.cgi'.format(self.base_url)
        # this request will reply with a 302 Found, we don't want to be redirected just yet in order to do error handling
        start_page = session.post(login_url, allow_redirects = False, data = login_payload, timeout = 10, verify = self.ca_cert_bundle, headers = {'referer': '{}/login.htm'.format(self.base_url)})

        _LOGGER.debug('login.cgi start_page')
        _LOGGER.debug(start_page.status_code)
        _LOGGER.debug(start_page.headers['Location'])
        # Some error handling
        if start_page.headers['Location'] == '/login.htm?err=2':
            # There's still a session active, and only 1 active session is allowed
            _LOGGER.error('Could not log in to the device. Only one concurrent session is allowed.')
            return False

        if start_page.headers['Location'] != '/index.htm':
            _LOGGER.error('Could not log in to the device. Got redirected to {}'.format(start_page.headers['Location']))
            return False

        index_page = session.get('{}{}'.format(self.base_url, start_page.headers['Location']), timeout = 10, verify = self.ca_cert_bundle, headers = {'referer': '{}/login.htm'.format(self.base_url)})

        _LOGGER.debug('index.htm index_page')
        _LOGGER.debug(index_page.status_code)

        # this is the token that needs to be used to log out
        index_httoken_search = re.search("yH5BAEAAAAALAAAAAABAAEAAAIBRAA7(.+)\" border=0>", index_page.text)
        index_authenticity_token = base64.b64decode(index_httoken_search.group(1)).decode('utf-8')

        result = False
        try:
            data_url = '{}/cgi/cgi_clients.js?_tn={}'.format(self.base_url, index_authenticity_token, ts, ts)
            data_page = session.get(data_url, timeout = 10, verify = self.ca_cert_bundle, headers = {'referer': '{}/index.htm?t={}'.format(self.base_url, ts)})
            _LOGGER.debug('cgi_clients.js data_page')
            _LOGGER.debug(data_page.status_code)
            # response is a javascript file with various information, for now we just want the online clients.
            data_search = re.search("var online_client=\\[(.*?)\\];", data_page.text, re.DOTALL)
            result = data_search.group(1).split('\n,')
        except requests.exceptions.Timeout:
            _LOGGER.error('Could not fetch cgi_clients, a timeout occurred.')

        # log out using the token we stored earlier
        logout_payload = {
            "httoken": index_authenticity_token
        }

        logout_url = '{}/logout.cgi'.format(self.base_url)
        log_out_page = session.post(logout_url, data = logout_payload, timeout = 10, verify=False, headers = {'referer': '{}/index.htm'.format(self.base_url)})

        now = dt_util.now()

        # start with an empty list, we will add all the devices we see
        last_results = []
        if result:
            _LOGGER.info('Got {} devices'.format(len(result)))
            for line in result:
                # Get rid of the single quotes
                device = [item.replace("'", "") for item in line.split(',')]
                # Parse the raw line
                name = device[0]
                ip = device[1]
                mac = device[2]

                _LOGGER.debug(device)

                last_results.append(Device(mac.upper(), name, ip, now))

            # replace the last results list, any devices that left will eventually report "not_home"
            self.last_results = last_results
            return True
        _LOGGER.error('Got no devices')
        return False
