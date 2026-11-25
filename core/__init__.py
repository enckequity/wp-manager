"""wp-manager core: pure logic and HTTP transport behind the agent tools (tools.py).

The TeamShift build ships no dashboard backend or Desktop page: the dashboard's update route ran
updates without the ``pre_tool_call`` approval hook, so every action goes through the tools.
"""

PLUGIN_ID = "wp-manager"
VERSION = "0.1.4"
CONNECTOR_NAMESPACE = "website-manager-hermes/v1"
CONNECTOR_SLUG = "website-manager-hermes-connector"
