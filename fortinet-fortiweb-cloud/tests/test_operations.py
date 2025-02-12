# Edit the config_and_params.json file and add the required parameter values.
# Add any specific assertions in each test case, based on the expected response.
# Add logic for validating conditional_output_schema.

"""
Copyright start
MIT License
Copyright (c) 2025 Fortinet Inc
Copyright end
"""

import pytest
from pprint import pformat
from testframework.conftest import initial_setup, info_json, params_json, validate_params, connector_id, connector_details,\
    valid_configuration, invalid_configuration, valid_configuration_with_token, conn_cleanup
from testframework.helpers.test_helpers import run_health_check_success, run_invalid_config_test, run_success_test,\
    run_output_schema_validation, run_invalid_param_test, set_report_metadata
from testframework.helpers.test_constants import VALID_CONFIG_TITLE, VALID_INPUT_TITLE, INVALID_PARAM_TITLE,\
    SCHEMA_VALIDATION_TITLE, STATUS_MISMATCH_ERROR
    

@pytest.mark.check_health
@pytest.mark.success
def test_check_health_success(valid_configuration, connector_details):
    set_report_metadata(connector_details, "Health Check", VALID_CONFIG_TITLE)
    result = run_health_check_success(valid_configuration, connector_details)
    assert result.get('status', '').lower() == 'available',\
        STATUS_MISMATCH_ERROR.format(expected='available', result=pformat(result))
    

@pytest.mark.check_health
@pytest.mark.invalid_input
def test_check_health_invalid_api_key(invalid_configuration, connector_id, connector_details, params_json):
    set_report_metadata(connector_details, "Health Check", INVALID_PARAM_TITLE.format(param='API Key'))
    result = run_invalid_config_test(invalid_configuration, connector_id, connector_details, param_name='api_key',
                                     param_type='password', config=params_json['config'])
    assert result.get('status', '').lower() == "disconnected",\
        STATUS_MISMATCH_ERROR.format(expected='disconnected', result=pformat(result))
    

@pytest.mark.check_health
@pytest.mark.invalid_input
def test_check_health_invalid_server_url(invalid_configuration, connector_id, connector_details, params_json):
    set_report_metadata(connector_details, "Health Check", INVALID_PARAM_TITLE.format(param='Server URL'))
    result = run_invalid_config_test(invalid_configuration, connector_id, connector_details, param_name='server_url',
                                     param_type='text', config=params_json['config'])
    assert result.get('status', '').lower() == "disconnected",\
        STATUS_MISMATCH_ERROR.format(expected='disconnected', result=pformat(result))
    

@pytest.mark.get_incident_dashboard_details
@pytest.mark.success
def test_get_incident_dashboard_details_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Dashboard Details", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_incident_dashboard_details',
                                   action_params=params_json['get_incident_dashboard_details']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_incident_dashboard_details
@pytest.mark.schema_validation
def test_validate_get_incident_dashboard_details_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Incident Dashboard Details", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_incident_dashboard_details', info_json, params_json['get_incident_dashboard_details'])

    

@pytest.mark.get_incident_dashboard_details
@pytest.mark.invalid_input
def test_get_incident_dashboard_details_invalid_time_range(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Dashboard Details", INVALID_PARAM_TITLE.format(param='Time Range'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_dashboard_details', param_name='time_range',
                                    param_type='text', action_params=params_json['get_incident_dashboard_details'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_incident_list
@pytest.mark.success
def test_get_incident_list_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incidents List", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_incident_list',
                                   action_params=params_json['get_incident_list']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_incident_list
@pytest.mark.schema_validation
def test_validate_get_incident_list_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Incidents List", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_incident_list', info_json, params_json['get_incident_list'])
    

@pytest.mark.get_incident_list
@pytest.mark.invalid_input
def test_get_incident_list_invalid_size(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incidents List", INVALID_PARAM_TITLE.format(param='Page Size'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_list', param_name='size',
                                    param_type='integer', action_params=params_json['get_incident_list'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_incident_list
@pytest.mark.invalid_input
def test_get_incident_list_invalid_page(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incidents List", INVALID_PARAM_TITLE.format(param='Page Number'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_list', param_name='page',
                                    param_type='integer', action_params=params_json['get_incident_list'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_incident_list
@pytest.mark.invalid_input
def test_get_incident_list_invalid_filter(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incidents List", INVALID_PARAM_TITLE.format(param='Filter'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_list', param_name='filter',
                                    param_type='json', action_params=params_json['get_incident_list'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_incident_list
@pytest.mark.invalid_input
def test_get_incident_list_invalid_time_range(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incidents List", INVALID_PARAM_TITLE.format(param='Time Range'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_list', param_name='time_range',
                                    param_type='text', action_params=params_json['get_incident_list'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_incident_details
@pytest.mark.success
def test_get_incident_details_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Details", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_incident_details',
                                   action_params=params_json['get_incident_details']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))

    

@pytest.mark.get_incident_details
@pytest.mark.invalid_input
def test_get_incident_details_invalid_incident_id(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Details", INVALID_PARAM_TITLE.format(param='Incident ID'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_details', param_name='incident_id',
                                    param_type='text', action_params=params_json['get_incident_details'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_incident_timeline_details
@pytest.mark.success
def test_get_incident_timeline_details_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Timeline Details", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_incident_timeline_details',
                                   action_params=params_json['get_incident_timeline_details']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_incident_timeline_details
@pytest.mark.schema_validation
def test_validate_get_incident_timeline_details_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Incident Timeline Details", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_incident_timeline_details', info_json, params_json['get_incident_timeline_details'])
    

@pytest.mark.get_incident_timeline_details
@pytest.mark.invalid_input
def test_get_incident_timeline_details_invalid_incident_id(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Timeline Details", INVALID_PARAM_TITLE.format(param='Incident ID'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_timeline_details', param_name='incident_id',
                                    param_type='text', action_params=params_json['get_incident_timeline_details'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_insight_events_summary
@pytest.mark.success
def test_get_insight_events_summary_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Insight Events Summary", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_insight_events_summary',
                                   action_params=params_json['get_insight_events_summary']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_insight_events_summary
@pytest.mark.schema_validation
def test_validate_get_insight_events_summary_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Insight Events Summary", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_insight_events_summary', info_json, params_json['get_insight_events_summary'])
    

@pytest.mark.get_incident_aggregated_details
@pytest.mark.success
def test_get_incident_aggregated_details_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Aggregated Details", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_incident_aggregated_details',
                                   action_params=params_json['get_incident_aggregated_details']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_incident_aggregated_details
@pytest.mark.schema_validation
def test_validate_get_incident_aggregated_details_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Incident Aggregated Details", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_incident_aggregated_details', info_json, params_json['get_incident_aggregated_details'])
    

@pytest.mark.get_incident_aggregated_details
@pytest.mark.invalid_input
def test_get_incident_aggregated_details_invalid_incident_id(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Incident Aggregated Details", INVALID_PARAM_TITLE.format(param='Incident ID'))
    result = run_invalid_param_test(connector_details, operation_name='get_incident_aggregated_details', param_name='incident_id',
                                    param_type='text', action_params=params_json['get_incident_aggregated_details'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_insight_events
@pytest.mark.success
def test_get_insight_events_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Insight Events", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_insight_events',
                                   action_params=params_json['get_insight_events']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_insight_events
@pytest.mark.schema_validation
def test_validate_get_insight_events_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get Insight Events", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_insight_events', info_json, params_json['get_insight_events'])

    

@pytest.mark.get_ip_protection
@pytest.mark.success
def test_get_ip_protection_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get IP Protection", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_ip_protection',
                                   action_params=params_json['get_ip_protection']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.get_ip_protection
@pytest.mark.schema_validation
def test_validate_get_ip_protection_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Get IP Protection", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'get_ip_protection', info_json, params_json['get_ip_protection'])
    

@pytest.mark.get_ip_protection
@pytest.mark.invalid_input
def test_get_ip_protection_invalid_epid(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get IP Protection", INVALID_PARAM_TITLE.format(param='Application ID'))
    result = run_invalid_param_test(connector_details, operation_name='get_ip_protection', param_name='epid',
                                    param_type='text', action_params=params_json['get_ip_protection'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.add_ip_protection
@pytest.mark.success
def test_add_ip_protection_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Add IP Protection", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='add_ip_protection',
                                   action_params=params_json['add_ip_protection']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.add_ip_protection
@pytest.mark.schema_validation
def test_validate_add_ip_protection_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Add IP Protection", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'add_ip_protection', info_json, params_json['add_ip_protection'])
    

@pytest.mark.add_ip_protection
@pytest.mark.invalid_input
def test_add_ip_protection_invalid_ipaddress(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Add IP Protection", INVALID_PARAM_TITLE.format(param='IP Address'))
    result = run_invalid_param_test(connector_details, operation_name='add_ip_protection', param_name='ipaddress',
                                    param_type='text', action_params=params_json['add_ip_protection'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.add_ip_protection
@pytest.mark.invalid_input
def test_add_ip_protection_invalid_epid(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Add IP Protection", INVALID_PARAM_TITLE.format(param='Application ID'))
    result = run_invalid_param_test(connector_details, operation_name='add_ip_protection', param_name='epid',
                                    param_type='text', action_params=params_json['add_ip_protection'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.delete_ip_protection
@pytest.mark.success
def test_delete_ip_protection_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete IP Protection", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='delete_ip_protection',
                                   action_params=params_json['delete_ip_protection']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.delete_ip_protection
@pytest.mark.schema_validation
def test_validate_delete_ip_protection_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Delete IP Protection", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'delete_ip_protection', info_json, params_json['delete_ip_protection'])

    

@pytest.mark.delete_ip_protection
@pytest.mark.invalid_input
def test_delete_ip_protection_invalid_epid(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Delete IP Protection", INVALID_PARAM_TITLE.format(param='Application ID'))
    result = run_invalid_param_test(connector_details, operation_name='delete_ip_protection', param_name='epid',
                                    param_type='text', action_params=params_json['delete_ip_protection'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.get_application_list
@pytest.mark.success
def test_get_application_list_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Get Applications List", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='get_application_list',
                                   action_params=params_json['get_application_list']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.update_geo_ip_block_list
@pytest.mark.success
def test_update_geo_ip_block_list_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Update Geo IP Block List", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='update_geo_ip_block_list',
                                   action_params=params_json['update_geo_ip_block_list']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.update_geo_ip_block_list
@pytest.mark.schema_validation
def test_validate_update_geo_ip_block_list_output_schema(cache, valid_configuration_with_token, connector_details,
                                                 info_json, params_json):
    set_report_metadata(connector_details, "Update Geo IP Block List", SCHEMA_VALIDATION_TITLE)
    run_output_schema_validation(cache, 'update_geo_ip_block_list', info_json, params_json['update_geo_ip_block_list'])
    

@pytest.mark.update_geo_ip_block_list
@pytest.mark.invalid_input
def test_update_geo_ip_block_list_invalid_epid(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Update Geo IP Block List", INVALID_PARAM_TITLE.format(param='Application ID'))
    result = run_invalid_param_test(connector_details, operation_name='update_geo_ip_block_list', param_name='epid',
                                    param_type='text', action_params=params_json['update_geo_ip_block_list'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    

@pytest.mark.execute_an_api_call
@pytest.mark.success
def test_execute_an_api_call_success(cache, valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Execute an API Request", VALID_INPUT_TITLE)
    for result in run_success_test(cache, connector_details, operation_name='execute_an_api_call',
                                   action_params=params_json['execute_an_api_call']):
        assert result.get('status') == "Success",\
            STATUS_MISMATCH_ERROR.format(expected='Success', result=pformat(result))


@pytest.mark.execute_an_api_call
@pytest.mark.invalid_input
def test_execute_an_api_call_invalid_endpoint(valid_configuration_with_token, connector_details, params_json):
    set_report_metadata(connector_details, "Execute an API Request", INVALID_PARAM_TITLE.format(param='Endpoint'))
    result = run_invalid_param_test(connector_details, operation_name='execute_an_api_call', param_name='endpoint',
                                    param_type='text', action_params=params_json['execute_an_api_call'])
    assert result.get('status') == "failed",\
        STATUS_MISMATCH_ERROR.format(expected='failed', result=pformat(result))
    
