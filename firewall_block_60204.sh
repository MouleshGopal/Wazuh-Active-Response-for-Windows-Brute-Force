#!/bin/bash
#
# Active Response script for rule 60204
# Runs on Wazuh Manager (Linux)
# Tells Windows agent to execute firewall-blocker.bat
#

RULE_ID="$1"
AGENT_ID="$2"

# Full path to the BAT file on the Windows agent
BAT_PATH="C:\\Wazuh\\active-responses\\bin\\firewall-blocker.bat"

# Log (optional but VERY useful)
LOG_FILE="/var/ossec/logs/active-responses.log"
echo "$(date) Rule $RULE_ID triggered on agent $AGENT_ID" >> "$LOG_FILE"

# Tell the agent to run the BAT file
/var/ossec/bin/agent_control -i "$AGENT_ID" -c "run $BAT_PATH"

exit 0
