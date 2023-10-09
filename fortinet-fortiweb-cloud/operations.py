import requests, json
import urllib.parse
from .constants import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('fortinet-fortiweb-cloud')


class FortiWeb(object):
    def __init__(self, config, *args, **kwargs):
        self.api_key = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/v2'.format(url)
        else:
            self.url = url + '/v2'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            headers = {
                'Content-Type': 'application/json',
                'Authorization': 'Basic ' + self.api_key
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, headers=headers, verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            else:
                logger.error("{0}".format(response.status_code))
                raise ConnectorError("{0}:{1}".format(response.status_code, response.text))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def get_incident_dashboard_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/dashboard'
        query_params = {
            'widget_id': WIDGET_NAMES.get(params.get('widget_id')),
            'action': params.get('action').lower() if params.get('action') else '',
            'host': params.get('host'),
            'time_range': params.get('time_range')
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ''}
        response = fw.make_rest_call(endpoint, 'GET', params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_list(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/incidents'
        if params.get('filter'):
            filter = json.dumps(params.get('filter'))
            filter = urllib.parse.quote(filter)
            endpoint = endpoint + '?filter={0}'.format(filter)
        query_params = {
            'time_range': params.get('time_range'),
            'size': params.get('size'),
            'page': params.get('page')
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ''}
        response = fw.make_rest_call(endpoint, 'GET', params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/incidents/{0}'.format(params.get('incident_id'))
        response = fw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_timeline_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/incidents/{0}/timeline'.format(params.get('incident_id'))
        response = fw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_insight_events_summary(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/insight/summary'
        response = fw.make_rest_call(endpoint, 'GET')
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_incident_aggregated_details(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/incidents/{0}/aggs'.format(params.get('incident_id'))
        query_params = {
            'name': GROUP_BY.get(params.get('name'))
        }
        response = fw.make_rest_call(endpoint, 'GET', params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def get_insight_events(config, params):
    try:
        fw = FortiWeb(config)
        endpoint = '/threat_analytics/insight'
        query_params = {
            'type': EVENT_TYPE.get(params.get('type')),
            'cursor': params.get('cursor'),
            'size': params.get('size'),
            'forward': params.get('forward')
        }
        query_params = {k: v for k, v in query_params.items() if v is not None and v != ''}
        response = fw.make_rest_call(endpoint, 'GET', params=query_params)
        return response
    except Exception as err:
        raise ConnectorError(str(err))


def check_health(config):
    try:
        response = get_incident_list(config, params={'time_range': '7d'})
        if response:
            return True
    except Exception as err:
        logger.info(str(err))
        raise ConnectorError(str(err))


operations = {
    'get_incident_dashboard_details': get_incident_dashboard_details,
    'get_incident_list': get_incident_list,
    'get_incident_details': get_incident_details,
    'get_incident_timeline_details': get_incident_timeline_details,
    'get_insight_events_summary': get_insight_events_summary,
    'get_incident_aggregated_details': get_incident_aggregated_details,
    'get_insight_events': get_insight_events
}
