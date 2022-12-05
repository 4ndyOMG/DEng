# DEng - Azure AD - Multi-Factor Authentication Request Generation

## Detection Requirement

To detect Multi-Factor Authentication Request Generation, also known as MFA Fatigue or MFA Brute Force, a credential access technique against Azure Active Directory. The remainder of this text will refer to this technique as MFA Fatigue.

**Vulnerability**
Fatigue can be defined as *weakness in metal or other materials caused by repeated variations of stress.* This MFA bypass vulnerability exploits the human by sending repeated MFA requests creating a weakness and gaining approval.

## Threat
**Intent**. Many adversary groups have used this method to gain access to valid credentials. Mitre ATT&CK lists two groups using this technique [APT29](https://attack.mitre.org/groups/G0016) and [LAPSUS$](https://attack.mitre.org/groups/G1004)

**Opportunity**. Organisations that have adopted MFA without number matching are vulnerable to this attack providing opportunity to the adversary. 

**Capability**. The exploitation of MFA fatigue in Azure AD would be simple for any adversary to implement.

## Data Source
Azure AD Sign-in logs are required to detect MFA Fatigue against Azure AD. The particular fields of interest to detect MFA Fatigue are; ResultType, CorrelationId and Authentication details. Azure AD Sigin-in schema defines these fields as:

**ResultType** - The result of the sign-in operation can be 0 for success or an error code for failure.

**Correlation ID** - The correlation ID groups sign-ins from the same sign-in session. The identifier was implemented for convenience. Its accuracy is not guaranteed because the value is based on parameters passed by a client.

**Authentication Details** provides the following information for each authentication attempt:
- A list of authentication policies applied, such as Conditional Access or Security Defaults.
- A list of session lifetime policies applied, such as Sign-in frequency or Remember MFA.
- The sequence of authentication methods used to sign-in.
- If the authentication attempt was successful and the reason why.
This information allows you to troubleshoot each step in a user’s sign-in. Use these details to track:
- The volume of sign-ins protected by MFA.
- The reason for the authentication prompt, based on the session lifetime policies.
- Usage and success rates for each authentication method.
- Usage of passwordless authentication methods, such as Passwordless Phone Sign-in, FIDO2, and Windows Hello for Business.
- How frequently authentication requirements are satisfied by token claims, such as when users aren't interactively prompted to enter a password or enter an SMS OTP.

The ResultTypes of interest are:
- 50074 - User did not pass the MFA challenge.
- 0 - Success
- 50140 - This error occurred due to 'Keep me signed in' interrupt when the user was signing-in.

### Goal
This detection is to identify adversaries that have successfully exploited users through MFA Fatigue. 
### Categorization
[Multi-Factor Authentication Request Generation, Technique T1621 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1621/)
### Strategy Abstract
To detect the successful exploitation of MFA Fatigue in Azure AD the analytic counts the number of failed MFA events before successful login. If the amount of fails exceeds the threshold the detection will alert. 
### Technical Context
A user that denies a MFA push notification will generate a single 50074 event regardless of the amount of failures. Failures beyond the single deny are tracked and published within Authentication Details as part of the next event; this can be either 50140 when show keep user signed in is set to yes; (Azure AD > User Settings> Show Keep user signed in), can also be disabled through conditional access policy (session > Persistent browser session) or ResultType 0 when 50140 disabled.

The detection first identifies the CorrelationId of all users that have failed a MFA challenge with ResultType 50074. The detection then joins the CorrelationId, with a join kind of leftsemi, with all users that have received ResultType 0 or 50140. 

The authentication details are then expanded to a line for each event before filtering on only those event that contain MFA Deny. These events are the counted by the CorrelationID before being compared against the threshold.

Please note the next event following the failure contains the authentication details of each failure and continues to record each failure until success. This analytic uses dcount() to count the number of distinct values to be compared against the threshold. 

The threshold is a static number set by the detection engineer. This threshold should be refined to each Azure Directory to reduce false positive whilst preventing false negatives which is known as detection precision. 

### Blind Spots and Assumptions
It is assumed that the adversary will send all MFA attempts in a single session. 
### False Positives
Users having a bad day.
### Validation
Validated against basic testing in Azure AD.
### Priority
High
#### Response
Confirm user location, IP address, user agent, is this in context with the users normal behavior? If deemed a true positive immediately reset user password and remove all user sessions. Enable number matching for MFA to mitigate this vulnerability.
#### Additional Resources
[Alerting and Detection Strategy Framework | by Palantir | Palantir Blog](https://blog.palantir.com/alerting-and-detection-strategy-framework-52dc33722df2)
[Sign-in log schema in Azure Monitor - Microsoft Entra | Microsoft Learn](https://learn.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-azure-monitor-sign-ins-log-schema)
[join operator - Azure Data Explorer | Microsoft Learn](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/joinoperator?pivots=azuredataexplorer)
https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/dcount-aggfunction

~~~kql
let lookback = ago(1d);
let threshold = 5;
SigninLogs
| where TimeGenerated > lookback
| where ResultType == 50074
| summarize by CorrelationId
| join kind=rightsemi ( 
SigninLogs
| where TimeGenerated > lookback
| where ResultType == 0
    or ResultType == 50140
| where AuthenticationDetails contains "MFA denied"
) on CorrelationId
| extend _authDetails = todynamic(AuthenticationDetails)
| mv-expand _authDetails
| where _authDetails contains "MFA denied"
| summarize dcount(tostring(_authDetails)) by CorrelationId, UserPrincipalName
| where dcount__authDetails > threshold
~~~
