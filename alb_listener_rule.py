#!/usr/bin/python

DOCUMENTATION = '''
---
module: alb_listener_rule
short_description: create or delete a listener rule
description:
  - Creates or deletes listener rules.
author:
    - "Pablo Munoz"
requirements: [ json, botocore, boto3 ]
options:
    state:
        description:
          - The desired state of the listener rule
        required: false
        default: present
        choices: ["present", "absent"]
    listener_arn:
        description:
          - The listener for the rule
        required: true
    priority:
        description:
          - The priority of the rule
        required: false
    conditions:
        description:
          - The rule conditions
        required: true
    actions:
        description:
          - The rule actions
        required: false
extends_documentation_fragment:
    - aws
    - ec2
'''

EXAMPLES = '''
# Note: These examples do not set authentication details, see the AWS Guide for details.
- alb_listener_rule:
    state: "present"
# Simple example to delete
- alb_listener_rule:
    state: "absent"
'''

RETURN = '''
listener_rule:
    description: Details of created or deleted listener rule.
    returned: when creating, deleting or modifying a listener rule
    type: complex
    contains:
        listener_arn:
            description: The listener for the rule
            returned: always
            type: string
        required: true
        rule_arn:
            description: The Amazon Resource Name (ARN) of the listener rule.
            returned: always
            type: string
        is_default:
            description: The name of the target group.
            returned: always
            type: string
        priotiry:
            description:
            returned: always
            type: bool
        actions:
            description:
            returned: always
            type: complex
            contains:
        conditions:
            description:
            returned: always
            type: complex
            contains:
'''
try:
    import boto3
    import botocore
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ec2 import boto3_conn, ec2_argument_spec, get_aws_connection_info


class ListenerRuleManager:
    """Handles Listener Rules"""

    def __init__(self, module):
        self.module = module

        try:
            region, ec2_url, aws_connect_kwargs = get_aws_connection_info(module, boto3=True)
            if not region:
                module.fail_json(msg="Region must be specified as a parameter, in EC2_REGION or AWS_REGION environment variables or in boto configuration file")
            self.elbv2 = boto3_conn(module, conn_type='client', resource='elbv2', region=region, endpoint=ec2_url, **aws_connect_kwargs)
        except boto.exception.NoAuthHandlerFound as e:
            self.module.fail_json(msg="Can't authorize connection - %s" % str(e))

    def get_next_free_priority(self, listener_arn):
        response = self.elbv2.describe_rules(ListenerArn=listener_arn)
        if len(response['Rules']) > 0:
            return max([int(rule['Priority']) for rule in response['Rules']
                        if rule['Priority'] != 'default']) + 1
        else:
            return 1

    def __find_in_array(self, array_of_rules, conditions):
        for c in array_of_rules:
            if c['Conditions'] == conditions:
                return c
        return None

    def describe_listener_rule(self, listener_arn, conditions):
        try:
            response = self.elbv2.describe_rules(
                ListenerArn=listener_arn)
            if len(response['Rules']) > 0:
                return self.__find_in_array(response['Rules'], conditions)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'ListenerNotFound':
                return None

        raise StandardError("Unknown problem describing %s listener rule %s." % (listener_arn, rule_arn))

    def is_matching_listener_rule(self, expected, existing):
        if expected['priority'] is not None and expected['priority'] != existing['Priority']:
            return False
        if expected['actions'] != existing['Actions']:
            return False

        return True

    def create_listener_rule(self, **args):
        response = self.elbv2.create_rule(**args)
        return response['Rules'][0]

    def modify_listener_rule(self, **args):
        response = self.elbv2.modify_rule(**args)
        return response['Rules'][0]

    def delete_listener_rule(self, rule_arn):
        return self.elbv2.delete_rule(RuleArn=rule_arn)


def main():
    argument_spec = ec2_argument_spec()
    argument_spec.update(dict(
        state=dict(required=False, choices=['present', 'absent'], default='present'),
        listener_arn=dict(required=True, type='str'),
        priority=dict(required=False, type='int'),
        conditions=dict(required=True, type='list'),
        actions=dict(required=False, type='list')
    ))

    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    if not HAS_BOTO3:
        module.fail_json(msg='boto3 is required.')

    if module.params['state'] == 'present':
        if 'actions' not in module.params and module.params['actions'] is None or not module.params['actions']:
            module.fail_json(msg="To create a listener rule its actions must be specified")

    listener_rule_manager = ListenerRuleManager(module)
    try:
        existing = listener_rule_manager.describe_listener_rule(
            module.params['listener_arn'], module.params['conditions'])
    except Exception as e:
        module.fail_json(msg="Exception describing listener rule with conditions "+module.params['conditions']+" for Listener '"+module.params['listener_arn']+"': "+str(e))

    results = dict(changed=False)
    if module.params['state'] == 'present':
        matching = False
        update = False
        if existing:
            if listener_rule_manager.is_matching_listener_rule(module.params, existing):
                matching = True
                results['Rule'] = existing
            else:
                update = True

        if not matching:
            if not module.check_mode:
                args = {}
                if module.params['actions']:
                    args['Actions'] = module.params['actions']

                if update:
                    args['RuleArn'] = existing['RuleArn']
                    if module.params['priority'] is not None and module.params['priority'] != existing['Priority']:
                        module.fail_json(msg="Priority can not be modified for an exitsing rule")
                    response = listener_rule_manager.modify_listener_rule(**args)
                else:
                    if module.params['priority']:
                        args['Priority'] = module.params['priority']
                    else:
                        args['Priority'] = listener_rule_manager.get_next_free_priority(module.params['listener_arn'])

                    args.update({
                        'ListenerArn': module.params['listener_arn'],
                        'Conditions': module.params['conditions']
                    })
                    response = listener_rule_manager.create_listener_rule(**args)

                results['Rule'] = response

            results['changed'] = True

    elif module.params['state'] == 'absent':
        if not existing:
            pass
        else:
            # it exists, so we should delete it and mark changed.
            # return info about the cluster deleted
            results['Rule'] = existing
            if not module.check_mode:
                try:
                    listener_rule_manager.delete_listener_rule(existing['RuleArn'])
                except botocore.exceptions.ClientError as e:
                    module.fail_json(msg=e.message)
            results['changed'] = True

    module.exit_json(**results)


if __name__ == '__main__':
    main()