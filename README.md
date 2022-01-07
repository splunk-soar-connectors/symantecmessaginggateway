[comment]: # "Auto-generated SOAR connector documentation"
# Symantec Messaging Gateway

Publisher: Splunk  
Connector Version: 2\.0\.2  
Product Vendor: Symantec  
Product Name: Messaging Gateway  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.9\.39220  

This app integrates with an instance of Symantec Messaging Gateway to perform containment and corrective actions

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Messaging Gateway asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | URL
**verify\_server\_cert** |  optional  | boolean | Verify Server Certificate
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

This action will add an email address to the list of <b>Local Bad Sender Domains</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to blocklist | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblocklist email'
Remove an email from the bad sender list

Type: **correct**  
Read only: **False**

This action will remove an email address from the list of <b>Local Bad Sender Domains</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**email** |  required  | Email to unblocklist | string |  `email` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.email | string |  `email` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'blocklist domain'
Add a domain to the bad sender list

Type: **contain**  
Read only: **False**

This action will add a domain to the list of <b>Local Bad Sender Domains</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to blocklist | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblocklist domain'
Remove a domain from the bad sender list

Type: **correct**  
Read only: **False**

This action will remove a domain from the list of <b>Local Bad Sender Domains</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**domain** |  required  | Domain to unblocklist | string |  `domain`  `url` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.domain | string |  `domain`  `url` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'blocklist ip'
Add an IP to the bad sender list

Type: **contain**  
Read only: **False**

This action will add an IP address to the list of <b>Local Bad Sender IPs</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to blocklist | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblocklist ip'
Remove an IP from the bad sender list

Type: **correct**  
Read only: **False**

This action will remove an IP address from the list of <b>Local Bad Sender IPs</b>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to unblocklist | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 