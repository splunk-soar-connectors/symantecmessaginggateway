[comment]: # "Auto-generated SOAR connector documentation"
# Symantec Messaging Gateway

Publisher: Splunk  
Connector Version: 2.0.5  
Product Vendor: Symantec  
Product Name: Messaging Gateway  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.2.0  

This app integrates with an instance of Symantec Messaging Gateway to perform containment and corrective actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Messaging Gateway asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL
**verify_server_cert** |  optional  | boolean | Verify Server Certificate
**username** |  required  | string | Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the supplied credentials with the SMG server  
[blocklist email](#action-blocklist-email) - Add an email to the bad sender list  
[unblocklist email](#action-unblocklist-email) - Remove an email from the bad sender list  
[blocklist domain](#action-blocklist-domain) - Add a domain to the bad sender list  
[unblocklist domain](#action-unblocklist-domain) - Remove a domain from the bad sender list  
[blocklist ip](#action-blocklist-ip) - Add an IP to the bad sender list  
[unblocklist ip](#action-unblocklist-ip) - Remove an IP from the bad sender list  

## action: 'test connectivity'
Validate the supplied credentials with the SMG server

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'blocklist email'
Add an email to the bad sender list

Type: **contain**  
Read only: **False**

This action will add an email address to the list of <b>Local Bad Sender Domains</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to blocklist | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email | string |  `email`  |   splunk@splunk.com 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully blocklisted email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unblocklist email'
Remove an email from the bad sender list

Type: **correct**  
Read only: **False**

This action will remove an email address from the list of <b>Local Bad Sender Domains</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to unblocklist | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.email | string |  `email`  |   splunk@splunk.com 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully unblocklisted email 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'blocklist domain'
Add a domain to the bad sender list

Type: **contain**  
Read only: **False**

This action will add a domain to the list of <b>Local Bad Sender Domains</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to blocklist | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.domain | string |  `domain`  `url`  |   splunk.com 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully blocklisted domain 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unblocklist domain'
Remove a domain from the bad sender list

Type: **correct**  
Read only: **False**

This action will remove a domain from the list of <b>Local Bad Sender Domains</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to unblocklist | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.domain | string |  `domain`  `url`  |   splunk.com  www.splunk.com 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Given value not found in blocklist. Item cannot be unblocklisted. 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'blocklist ip'
Add an IP to the bad sender list

Type: **contain**  
Read only: **False**

This action will add an IP address to the list of <b>Local Bad Sender IPs</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to blocklist | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  |   10.10.10.10  3.3.3.1 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully blocklisted IP 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'unblocklist ip'
Remove an IP from the bad sender list

Type: **correct**  
Read only: **False**

This action will remove an IP address from the list of <b>Local Bad Sender IPs</b>.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to unblocklist | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.ip | string |  `ip`  |   10.10.10.10  3.3.3.1 
action_result.data | string |  |  
action_result.summary | string |  |  
action_result.message | string |  |   Successfully unblocklisted IP 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 