# dbedit tools

<!--- cspell:ignore Numebr --->
<!--- cspell:words HISTFILE whereused --->

This module provides tools for interacting with the Check Point dbedit tool.

## Testing

WIP tests in lab

### Deployment and run

``` shell
# --- customer deployment

# without the package dir
textpack -ce src/dbedit/
# at the target machine:
cd /opt/ntt/packages/
base64 -d | tar -xJf -
# ...

# -- lab deployment and test

# adds the "cp-py-tools" package dir
devtools/bin/deploy_to_remote.sh src/dbedit/

ssh -t nttlab_cpsms-1 "cd /opt/ntt/packages/ && unset HISTFILE && "

ssh nttlab_cpsms-1 "python3 /opt/ntt/packages/cp-py-tools/dbedit/query_objects.py -Q auto_calculated -F tsv"
ssh nttlab_cpsms-1 "python3 /opt/ntt/packages/cp-py-tools/dbedit/query_objects.py -Q auto_calculated -F csv" | code -
ssh nttlab_cpsms-1 "python3 /opt/ntt/packages/cp-py-tools/dbedit/query_objects.py -Q auto_calculated -F json" | jq .

dbedit -local
```

### Example dbedit session

``` shell-session
[Expert@lab-cpsms-1:0]# dbedit -local

Please enter a command, -h for help or -q to quit: 

dbedit> query network_objects cdm_auto_calculated='true'

Object Name: Net_192.168.144.10
Object UID: {194489F2-80B3-467E-8EAF-6FA39C598E0F}
...

dbedit> whereused network_objects lab-vsx-fw1_eth3.1011
Numebr of results: 0

dbedit> whereused network_objects Net_192.168.144.10
Numebr of results: 0

dbedit> whereused network_objects Net_10.111.111.111
Numebr of results: 1

Object Name: 
Object UID: {B765233E-CB55-B64C-929F-494347E7E013}
Class Name: referral
Fields Details
--------------
    last_element: false
    referral_info: emptyFieldName emptyFieldName 
    referral_obj: Name: lab-vsx-fw1_eth3.1011 (Table: network_objects)
    scheme_flags: 
    type: member

dbedit> print network_objects lab-vsx-fw1_eth3.1011

Object Name: lab-vsx-fw1_eth3.1011
Object UID: {F7C619C7-E5E6-4B68-9EF1-BB9A60BB373C}
Class Name: network_object_group
Table Name: network_objects
Last Modified by: username1
Last Modified from: localhost
Last Modification time: Fri Nov 12 12:21:34 2021
Fields Details
--------------
    : Name: Net_10.11.11.0 (Table: network_objects) Name: Net_10.111.111.111 (Table: network_objects) 
    cdm_auto_calculated: true
    color: black
    comments: 
    group_convention_query: 
    group_sort_type: 3
    ip_convention_object: NULL
    is_convention_on: false
    member_class: network_object
    members_query: 
    type: group

[Expert@lab-cpsms-1:0]# mgmt_cli -r true show generic-object uid B765233E-CB55-B64C-929F-494347E7E013
code: "generic_err_object_not_found"
message: "Requested object [b765233e-cb55-b64c-929f-494347e7e013] not found"

[Expert@lab-cpsms-1:0]# mgmt_cli -r true show object uid F7C619C7-E5E6-4B68-9EF1-BB9A60BB373C
object: 
  uid: "f7c619c7-e5e6-4b68-9ef1-bb9a60bb373c"
  name: "lab-vsx-fw1_eth3.1011"
  type: "group"
  domain: 
    uid: "41e821a0-3720-11e3-aa6e-0800200c9fde"
    name: "SMC User"
    domain-type: "domain"
  icon: "General/group"
  color: "black"

[Expert@lab-cpsms-1:0]# mgmt_cli -r true show group uid F7C619C7-E5E6-4B68-9EF1-BB9A60BB373C
uid: "f7c619c7-e5e6-4b68-9ef1-bb9a60bb373c"
name: "lab-vsx-fw1_eth3.1011"
type: "group"
...
```

`where-used` API call does not work on these objects:

``` shell-session
[Expert@lab-cpsms-1:0]# mgmt_cli -r true show network name Net_10.111.111.111
uid: "279e4010-393e-49d5-a6a5-5274da273558"
name: "Net_10.111.111.111"
type: "network"
...

[Expert@lab-cpsms-1:0]# mgmt_cli -r true show generic-object uid "279e4010-393e-49d5-a6a5-5274da273558"
domainsPreset: null
objectValidationState: null
...
type: "network"
...
ipaddr: "10.111.111.111"
cdmAutoCalculated: true
uid: "279e4010-393e-49d5-a6a5-5274da273558"
...

[Expert@lab-cpsms-1:0]# mgmt_cli -r true where-used name Net_10.111.111.111
code: "generic_err_object_not_found"
message: "Requested object [Net_10.111.111.111] not found"

[Expert@lab-cpsms-1:0]# mgmt_cli -r true where-used uid "279e4010-393e-49d5-a6a5-5274da273558"
code: "generic_err_object_not_found"
message: "Requested object [279e4010-393e-49d5-a6a5-5274da273558] not found"
```
