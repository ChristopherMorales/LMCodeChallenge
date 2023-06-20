import requests
import json
import ipaddress
from urllib.parse import quote


# Compliance requirement
blocked_ips = [
    '236.216.246.119',
    '109.3.194.189',
    '36.229.68.87',
    '21.90.154.237',
    '91.172.88.105'
]

blocked_ports = [22, 80, 443]

def is_compliant(rule):
    # Check if the rule allows traffic from the blocked IPs
    if rule['Direction'] == 'Ingress' and rule['FromPort'] and rule['Action'] == 'Allow' in blocked_ports:
        for ip_range in rule['IpRanges']:
            for blocked_ip in blocked_ips:
                # This tells all the usable addresses within the specified range
                if ipaddress.ip_address(blocked_ip) in ipaddress.ip_network(ip_range, strict=False):
                    return False
    return True

def get_firewall_rules(url):
    try:
        response = requests.get(url)
        data = response.json()
        rules = data['Items']
        last_evaluated_key = data.get('LastEvaluatedKey')
        return rules, last_evaluated_key
    except (requests.exceptions.RequestException, json.JSONDecodeError):
        return [], None

def write_compliance_results_json(results):
    with open('compliance_results.json', 'w') as file:
        json.dump(results, file, indent=4)

def url_encode(rule_id):
    json_string = json.dumps(rule_id)
    encoded_string = quote(json_string)
    return encoded_string

base_url = 'https://g326av89lk.execute-api.us-east-1.amazonaws.com/prod/rules'
url = base_url
rules = []
last_evaluated_key = None

while True:
    data, last_evaluated_key = get_firewall_rules(url)

    # Go through each rule and verifies if compliance
    for rule in data:
        rule_id = rule['RuleId']
        if is_compliant(rule):
            compliance = 'COMPLIANT'
        else:
            compliance = 'NON_COMPLIANT'
        # Save each rule in memory to print it later
        rules.append({'RuleId': rule_id, 'Compliance': compliance})

    if last_evaluated_key is None:
        break

    # Add the query parameter to go to the next page
    url = f'{base_url}?ExclusiveStartKey={url_encode(last_evaluated_key)}'
    print("API Call: " +url)

write_compliance_results_json(rules)
