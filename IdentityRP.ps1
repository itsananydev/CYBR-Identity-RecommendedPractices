$global:caConfiguration = ConvertFrom-Json -InputObject (Get-Content ".\CyberArkIdentityRP.json" | Out-String)
$global:caAuthentication = $null
$global:caToken = $null
$global:caWebSession = $null





function CAWriteLog
{
    Param ([string]$CALogLevel, [string]$CAMessage, [string]$CAMessage2, [string]$CAMessage3, [string]$CAMessage4, [string]$CAMessage5)
    $CATime = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $CALogMessage = "$CATime - $CALogLevel - $CAMessage $CAMessage2 $CAMessage3 $CAMessage4 $CAMessage5"
    Add-content -Path $global:caConfiguration.LogFile -Value $CALogMessage
}


############################ here we start.... #######################3
#Login
CAWriteLog "INFO" "#######################################                             ################################################"
CAWriteLog "INFO" "#######################################     Starting New Script     ################################################"
CAWriteLog "INFO" "#######################################                             ################################################"

$caBody = @{}
$caBody += @{"User" = $global:caConfiguration.API.Login.Username}
$caBody += @{"Version" = "1.0"}
$caBody += @{"TenantId" = $global:caConfiguration.API.Login.TenantId}
$caBody = $caBody | ConvertTo-Json

CAWriteLog "INFO" "Started First Authentication with body `n $caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Security/StartAuthentication") -body $caBody -ContentType "application/json"
CAWriteLog "INFO" "Received response of $caAPIResponse"

if($caAPIResponse.success -eq "True")
{
    $caBody = @{}
    $caBody += @{"Action" = "Answer"}
    $caBody += @{"SessionId" = $caAPIResponse.Result.SessionId}
    $caBody += @{"MechanismId" = $caAPIResponse.Result.Challenges.Mechanisms.MechanismId}
    $caBody += @{"Answer" = $global:caConfiguration.API.Login.Password}
    $caBody += @{"TenantId" = $global:caConfiguration.API.Login.TenantId}
    $caBody = $caBody | ConvertTo-Json
    CAWriteLog "INFO" "Started Second Authentication with body `n $caBody"
    $caAPIResponse2 = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Security/AdvanceAuthentication") -body $caBody -ContentType "application/json" -SessionVariable caWebSession
    CAWriteLog "INFO" "Received response of $caAPIResponse2"
 
    if($caAPIResponse2.success -eq "True")
    {
#       $global:caAuthorizationToken = @{"X-CENTRIFY-NATIVE-CLIENT" = "true"}
        $global:caAuthorizationToken = @{"X-IDAP-NATIVE-CLIENT" = "true"}
        $global:caAuthorizationToken += @{"Content-Type"= "application/json"}
        $global:caAuthorizationToken += @{"Authorization" = "Bearer AuthorizationToken"}
        CAWriteLog "INFO" "Successfully authenticated to CyberArk Identity"
    }
    else
    {
        CAWriteLog "ERROR" "Failed to advance the authentication at Security/AdvanceAuthentication !!!"
        exit 2
    }
}
else
{
    CAWriteLog "ERROR" "Failed to start the Authentication process at Security/StartAuthentication !!!"
    exit 1
}


############################################ Some General things... ##########################################################

New-Item -Path '.\Temp'-ItemType Directory
New-Item -Path '.\CyberArkIdentityRP.log'

#################################################################################################################################


#Create Auth Profiles

###### note: no changes to existing profiles including default... should be changed manually for now!!! 
CAWriteLog "INFO" "#############################      Authentication Profiles....... #######################"

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthPortalFullAdminAccessMFA"
$caBody = Get-Content ".\Data\AuthPortalFullAdminAccessMFA.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthPortalFullAdminAccessMFA"
    $global:caConfiguration.AuthenticationProfiles.AuthPortalFullAdminAccessMFAID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthPortalFullAdminAccessMFA"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthConnectorInstaller"
$caBody = Get-Content ".\Data\AuthConnectorInstaller.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthConnectorInstaller"
    $global:caConfiguration.AuthenticationProfiles.AuthConnectorInstallerID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthConnectorInstaller"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthSelfServicePasswordResetID"
$caBody = Get-Content ".\Data\AuthSelfServicePasswordReset.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthSelfServicePasswordResetID"
    $global:caConfiguration.AuthenticationProfiles.AuthSelfServicePasswordResetID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthSelfServicePasswordResetID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthBusinessUsersID"
$caBody = Get-Content ".\Data\AuthBusinessUsers.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthBusinessUsersID"
    $global:caConfiguration.AuthenticationProfiles.AuthBusinessUsersID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthBusinessUsersID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthBusinessUsersFirstLoginID"
$caBody = Get-Content ".\Data\AuthBusinessUsersFirstLogin.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthBusinessUsersFirstLoginID"
    $global:caConfiguration.AuthenticationProfiles.AuthBusinessUsersFirstLoginID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthBusinessUsersFirstLoginID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthADFSMFAID"
$caBody = Get-Content ".\Data\AuthADFSMFA.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthADFSMFAID"
    $global:caConfiguration.AuthenticationProfiles.AuthADFSMFAID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthADFSMFAID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthRadiusMFAID"
$caBody = Get-Content ".\Data\AuthRadiusMFA.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthRadiusMFAID"
    $global:caConfiguration.AuthenticationProfiles.AuthRadiusMFAID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthRadiusMFAID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthStepUpAuthenticationID"
$caBody = Get-Content ".\Data\AuthStepUpAuthentication.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthStepUpAuthenticationID"
    $global:caConfiguration.AuthenticationProfiles.AuthStepUpAuthenticationID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthStepUpAuthenticationID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthEndpointMFAID"
$caBody = Get-Content ".\Data\AuthEndpointMFA.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthEndpointMFAID"
    $global:caConfiguration.AuthenticationProfiles.AuthEndpointMFAID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthEndpointMFAID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthB2CUsersID"
$caBody = Get-Content ".\Data\AuthB2CUsers.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthB2CUsersID"
    $global:caConfiguration.AuthenticationProfiles.AuthB2CUsersID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthB2CUsersID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}

CAWriteLog "INFO" "Provisioning Authentication Profile - AuthB2CUsersFirstLoginID"
$caBody = Get-Content ".\Data\AuthB2CUsersFirstLogin.json" 
CAWriteLog "INFO" "Creating AuthProfile with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/AuthProfile/SaveProfile") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True"){
    CAWriteLog "INFO" "Successfully provisioned Authentication Profile - AuthB2CUsersFirstLoginID"
    $global:caConfiguration.AuthenticationProfiles.AuthB2CUsersFirstLoginID = ($caAPIResponse.Result)
}
else
{
    CAWriteLog "ERROR" "Failed to provision Authentication Profile - AuthB2CUsersFirstLoginID"
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 3}
}


#################################################################################################################################


# Create  users
CAWriteLog "INFO" "#############################      Creating Users....... #######################"

<# $caBody = Get-Content ".\Data\UserAdmin.json" | ConvertFrom-Json
$temp = $global:caConfiguration.API.Login.Username -Split("@")
$caBody.Name = -join('CAIdentityAdmin','@',$temp[1])
$caBody.DisplayName = $caBody.Name
$caBody.MobileNumber = $global:caConfiguration.API.Login.TenantAdminRealPhone
$caBody.OfficeNumber = $global:caConfiguration.API.Login.TenantAdminRealPhone
$caBody.Mail = $global:caConfiguration.API.Login.TenantAdminRealEmail
$caBody = $caBody | ConvertTo-Json

CAWriteLog "INFO" "Creating Admin User with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/CDirectoryService/CreateUser") -ContentType "application/json" -Headers $global:caAuthorizationToken -WebSession $caWebSession -body $caBody
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True")
{
    $global:caConfiguration.Users.AdminUID=($caAPIResponse.Result)
    CAWriteLog "INFO" "Admin User created successfully!!!"
}
else
{
    CAWriteLog "ERROR" "Failed to create Admin User, Exiting...."
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 4}
}
 #>

$caBody = Get-Content ".\Data\UserConnector.json" | ConvertFrom-Json
$temp = $global:caConfiguration.API.Login.Username -Split("@")
$caBody.Name = -join('CAIdentityConnector','@',$temp[1])
$caBody.DisplayName = $caBody.Name
#$caBody.MobileNumber = $global:caConfiguration.API.Login.TenantAdminRealPhone
#$caBody.OfficeNumber = $global:caConfiguration.API.Login.TenantAdminRealPhone
$caBody.Mail = $global:caConfiguration.API.Login.TenantAdminRealEmail
$caBody = $caBody | ConvertTo-Json

CAWriteLog "INFO" "Creating Connector User with body of:"
CAWriteLog "INFO" "$caBody"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/CDirectoryService/CreateUser") -ContentType "application/json" -Headers $global:caAuthorizationToken -WebSession $caWebSession -body $caBody
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if($caAPIResponse.success -eq "True")
{
    $global:caConfiguration.Users.ConnectorUID=($caAPIResponse.Result)
    CAWriteLog "INFO" "Connector User created successfully!!!"
}
else
{
    CAWriteLog "ERROR" "Failed to create Connector User, Exiting...."
    if($global:caConfiguration.ContinueOnError -eq "false")  {exit 4}
}


#################################################################################################################################

# Create Roles
CAWriteLog "INFO" "#############################      Roles....... #######################"
#----------------
CAWriteLog "INFO" "Provisioning Role - ConnectorInstallerID"
$caBody = Get-Content (".\Data\RoleConnectorInstaller.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - ConnectorInstaller"
        $global:caConfiguration.Roles.ConnectorInstallerID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - ConnectorInstaller"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - SelfServicePasswordResetID"
$caBody = Get-Content (".\Data\RoleSelfServicePasswordReset.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - SelfServicePasswordReset"
        $global:caConfiguration.Roles.SelfServicePasswordResetID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - SelfServicePasswordReset"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - BusinessUsers"
$caBody = Get-Content (".\Data\RoleBusinessUsers.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - BusinessUsers"
        $global:caConfiguration.Roles.BusinessUsersID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - BusinessUsers"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - ADFSMFA"
$caBody = Get-Content (".\Data\RoleADFSMFA.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - ADFSMFA"
        $global:caConfiguration.Roles.ADFSMFAID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - ADFSMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - RadiusMFA"
$caBody = Get-Content (".\Data\RoleRadiusMFA.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - RadiusMFA"
        $global:caConfiguration.Roles.RadiusMFAID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - RadiusMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - MobileRegistration"
$caBody = Get-Content (".\Data\RoleMobileRegistration.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - MobileRegistration"
        $global:caConfiguration.Roles.MobileRegistrationID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - MobileRegistration"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - EndpointMFA"
$caBody = Get-Content (".\Data\RoleEndpointMFA.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - EndpointMFA"
        $global:caConfiguration.Roles.EndpointMFAID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - EndpointMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - GlobalIdentityHelpDesk"
$caBody = Get-Content (".\Data\RoleGlobalIdentityHelpDesk.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - GlobalIdentityHelpDesk"
        $global:caConfiguration.Roles.GlobalIdentityHelpDeskID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - GlobalIdentityHelpDesk"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - GlobalIdentityAdministrator"
$caBody = Get-Content (".\Data\RoleGlobalIdentityAdministrator.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - GlobalIdentityAdministrator"
        $global:caConfiguration.Roles.GlobalIdentityAdministratorID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - GlobalIdentityAdministrator"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - GlobalIdentityAuditor"
$caBody = Get-Content (".\Data\RoleGlobalIdentityAuditor.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - GlobalIdentityAuditor"
        $global:caConfiguration.Roles.GlobalIdentityAuditorID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - GlobalIdentityAuditor"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }
#----------------
CAWriteLog "INFO" "Provisioning Role - B2CUsers"
$caBody = Get-Content (".\Data\RoleB2CUsers.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - B2CUsers"
        $global:caConfiguration.Roles.B2CUsersID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - B2CUsers"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }

#----------------
CAWriteLog "INFO" "Provisioning Role - WPM"
$caBody = Get-Content (".\Data\RoleWPM.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/SaasManage/StoreRole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Role - WPM"
        $global:caConfiguration.Roles.WPMID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Role - B2CUsers"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
    }

#----------------
CAWriteLog "INFO" "Provisioning Role Members - Connector Installer"

    $caBody = '{"Name":"'+[string]$global:caConfiguration.Roles.ConnectorInstallerID._RowKey+'","Users":{"Add": ["'+[string]$global:caConfiguration.Users.ConnectorUID+'"]}}'
    $caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/roles/updaterole") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
    CAWriteLog "INFO" "Response recieved as:"
    CAWriteLog "INFO" "$caAPIResponse"
    if ($caAPIResponse.success -eq "True"){
            CAWriteLog "INFO" "Successfully added user connector to Role - Connector Installer"
        }
        else
        {
            CAWriteLog "ERROR" "Failed adding user admin to Role - Connector Installer"
            if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
        }

#----------------
    CAWriteLog "INFO" "Provisioning Role permissions - All"

    ((Get-Content -path .\Data\RolesUpdate.json) -replace 'CAIdentityAdmin', $global:caConfiguration.Roles.GlobalIdentityAdministratorID._RowKey) | Set-Content -Path .\Temp\RolesUpdate.json
    ((Get-Content -path .\Temp\RolesUpdate.json) -replace 'CAIdentityHelpdesk', $global:caConfiguration.Roles.GlobalIdentityHelpDeskID._RowKey) | Set-Content -Path .\Temp\RolesUpdate.json
    ((Get-Content -path .\Temp\RolesUpdate.json) -replace 'CAIdentityAudit', $global:caConfiguration.Roles.GlobalIdentityAuditorID._RowKey) | Set-Content -Path .\Temp\RolesUpdate.json
    ((Get-Content -path .\Temp\RolesUpdate.json) -replace 'CAConnector', $global:caConfiguration.Roles.ConnectorInstallerID._RowKey) | Set-Content -Path .\Temp\RolesUpdate.json
    $caBody = Get-Content (".\Temp\RolesUpdate.json")

    $caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Roles/AssignSuperRights") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
    CAWriteLog "INFO" "Response recieved as:"
    CAWriteLog "INFO" "$caAPIResponse"
    if ($caAPIResponse.success -eq "True"){
            CAWriteLog "INFO" "Successfully added roles permissions"
        }
        else
        {
            CAWriteLog "ERROR" "Failed adding roles permissions"
            if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
        }


#---------------- Ilan, TBD
<# CAWriteLog "INFO" "Provisioning Role Members - System Administrator"

    $caBody = Get-Content (".\Data\RoleMembership.json")
    $caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/roles/UpdateRoleV2") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
    CAWriteLog "INFO" "Response recieved as:"
    CAWriteLog "INFO" "$caAPIResponse"
    if ($caAPIResponse.success -eq "True"){
            CAWriteLog "INFO" "Successfully added user membership to Roles"
        }
        else
        {
            CAWriteLog "ERROR" "Failed adding users to Roles"
            if($global:caConfiguration.ContinueOnError -eq "false")  {exit 5}
        }
 #>

#################################################################################################################################


# Create Orgnizations
<# 
CAWriteLog "INFO" "#############################      Organizations....... #######################"

CAWriteLog "INFO" "Provisioning Organization - Tenant"
$caBody = Get-Content (".\Data\OrgTenant.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Org/Create") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Organization - Tenant"
        $global:caConfiguration.Organizations.TenantID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Organization - Tenant"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 6}
    }

CAWriteLog "INFO" "Provisioning Organization - Global"
$caBody = Get-Content (".\Data\OrgGlobal.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Org/Create") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Organization - Global"
        $global:caConfiguration.Organizations.GlobalID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Organization - Global"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 6}
    }

CAWriteLog "INFO" "Provisioning Organization - Country1"
$caBody = Get-Content (".\Data\OrgCountry1.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Org/Create") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Organization - Country1"
        $global:caConfiguration.Organizations.Country1ID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Organization - Country1"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 6}
    }

CAWriteLog "INFO" "Provisioning Organization - Country2"
$caBody = Get-Content (".\Data\OrgCountry2.json")
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Org/Create") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Organization - Country2"
        $global:caConfiguration.Organizations.Country2ID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Organization - Country2"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 6}
    } 
    
#>
#----------------------------------------
<#
CAWriteLog "INFO" "Updating Organization - Tenant"
$caBody = '{"Name":"'+[string]$global:caConfiguration.Roles.ConnectorInstallerID._RowKey+'","Users":{"Add": ["'+[string]$global:caConfiguration.Users.ConnectorUID+'"]}}'
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Org/UpdateAdministrators") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Organization - Country2"
        $global:caConfiguration.Organizations.Country2ID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Organization - Country2"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 6}
    }

#>


#################################################################################################################################

#################################################################################################################################


# Create Policies
CAWriteLog "INFO" "#############################      Policies....... #######################"



#--------------------------------- B2C Users policy  -----------------------------------

((Get-Content -path .\Data\PolicyB2CUsers.json) -replace 'CADefaultAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthB2CUsersFirstLoginID.Uuid) | Set-Content -Path .\Temp\PolicyB2CUsers.json
((Get-Content -path .\Temp\PolicyB2CUsers.json) -replace 'CAAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthB2CUsersID.Uuid) | Set-Content -Path .\Temp\PolicyB2CUsers.json
((Get-Content -path .\Temp\PolicyB2CUsers.json) -replace 'CARole', $global:caConfiguration.Roles.B2CUsersID._RowKey) | Set-Content -Path .\Temp\PolicyB2CUsers.json
$caBody = Get-Content (".\Temp\PolicyB2CUsers.json")

CAWriteLog "INFO" "Provisioning Policy - B2CUsers"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - B2CUsers"
        $global:caConfiguration.Policies.B2CUsers = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - B2CUsers"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }





#--------------------------------- Business Users policy  -----------------------------------

((Get-Content -path .\Data\PolicyBusinessUsers.json) -replace 'CADefaultAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthBusinessUsersFirstLoginID.Uuid) | Set-Content -Path .\Temp\PolicyBusinessUsers.json
((Get-Content -path .\Temp\PolicyBusinessUsers.json) -replace 'CAAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthBusinessUsersID.Uuid) | Set-Content -Path .\Temp\PolicyBusinessUsers.json
((Get-Content -path .\Temp\PolicyBusinessUsers.json) -replace 'CARole', $global:caConfiguration.Roles.BusinessUsersID._RowKey) | Set-Content -Path .\Temp\PolicyBusinessUsers.json
$caBody = Get-Content (".\Temp\PolicyBusinessUsers.json")

CAWriteLog "INFO" "Provisioning Policy - BusinessUsers"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - BusinessUsers"
        $global:caConfiguration.Policies.BusinessUsers = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - BusinessUsers"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }



#--------------------------------- WPM policy  -----------------------------------

((Get-Content -path .\Data\PolicyWPM.json) -replace 'CARole', $global:caConfiguration.Roles.WPMID._RowKey) | Set-Content -Path .\Temp\PolicyWPM.json

$caBody = Get-Content (".\Temp\PolicyWPM.json")

CAWriteLog "INFO" "Provisioning Policy - WPM"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - WPM"
        $global:caConfiguration.Policies.WPM = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - WPM"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }




#--------------------------------- Radius MFA policy  -----------------------------------

$caBody = Get-Content (".\Data\IPRadiusMFA.json")
CAWriteLog "INFO" "Provisioning IP Range - Radius MFA"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/core/UpdatePremDetectRange") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned IP Range - Radius MFA"
        $global:caConfiguration.IPRange.RadiusMFAID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision IP Range - Radius MFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }

((Get-Content -path .\Data\PolicyRadiusMFA.json) -replace 'CAIPRange', $global:caConfiguration.IPRange.RadiusMFAID) | Set-Content -Path .\Temp\PolicyRadiusMFA.json
((Get-Content -path .\Temp\PolicyRadiusMFA.json) -replace 'CAAuthPolicy', $global:caConfiguration.AuthenticationProfiles.AuthRadiusMFAID.Uuid) | Set-Content -Path .\Temp\PolicyRadiusMFA.json
((Get-Content -path .\Temp\PolicyRadiusMFA.json) -replace 'CARole', $global:caConfiguration.Roles.RadiusMFAID._RowKey) | Set-Content -Path .\Temp\PolicyRadiusMFA.json
$caBody = Get-Content (".\Temp\PolicyRadiusMFA.json")

CAWriteLog "INFO" "Provisioning Policy - RadiusMFA"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - RadiusMFA"
        $global:caConfiguration.Policies.RadiusMFA = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - RadiusMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }

#--------------------------------- ADFS MFA policy  -----------------------------------

$caBody = Get-Content (".\Data\IPADFSMFA.json")
CAWriteLog "INFO" "Provisioning IP Range - ADFS MFA"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/core/UpdatePremDetectRange") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned IP Range - ADFS MFA"
        $global:caConfiguration.IPRange.ADFSMFAID = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision IP Range - ADFS MFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }

((Get-Content -path .\Data\PolicyADFSMFA.json) -replace 'CAIPRange', $global:caConfiguration.IPRange.ADFSMFAID) | Set-Content -Path .\Temp\PolicyADFSMFA.json
((Get-Content -path .\Temp\PolicyADFSMFA.json) -replace 'CAAuthPolicy', $global:caConfiguration.AuthenticationProfiles.AuthADFSMFAID.Uuid) | Set-Content -Path .\Temp\PolicyADFSMFA.json
((Get-Content -path .\Temp\PolicyADFSMFA.json) -replace 'CARole', $global:caConfiguration.Roles.ADFSMFAID._RowKey) | Set-Content -Path .\Temp\PolicyADFSMFA.json
$caBody = Get-Content (".\Temp\PolicyADFSMFA.json")

CAWriteLog "INFO" "Provisioning Policy - ADFSMFA"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - ADFSMFA"
        $global:caConfiguration.Policies.ADFSMFA = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - ADFSMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }






#--------------------------------- Self Service Password Reset policy  -----------------------------------
((Get-Content -path .\Data\PolicySelfServicePasswordReset.json) -replace 'CAAuthPolicy', $global:caConfiguration.AuthenticationProfiles.AuthSelfServicePasswordResetID.Uuid) | Set-Content -Path .\Temp\PolicySelfServicePasswordReset.json
((Get-Content -path .\Temp\PolicySelfServicePasswordReset.json) -replace 'CARole', $global:caConfiguration.Roles.SelfServicePasswordResetID._RowKey) | Set-Content -Path .\Temp\PolicySelfServicePasswordReset.json
$caBody = Get-Content (".\Temp\PolicySelfServicePasswordReset.json")

CAWriteLog "INFO" "Provisioning Policy - SelfServicePasswordReset"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - SelfServicePasswordReset"
        $global:caConfiguration.Policies.SelfServicePasswordReset = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - SelfServicePasswordReset"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }




#--------------------------------- Endpoint MFA policy  -----------------------------------
((Get-Content -path .\Data\PolicyEndpointMFA.json) -replace 'CADefaultAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthEndpointMFAID.Uuid) | Set-Content -Path .\Temp\PolicyEndpointMFA.json
((Get-Content -path .\Temp\PolicyEndpointMFA.json) -replace 'CAAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthEndpointMFAID.Uuid) | Set-Content -Path .\Temp\PolicyEndpointMFA.json
((Get-Content -path .\Temp\PolicyEndpointMFA.json) -replace 'CARole', $global:caConfiguration.Roles.EndpointMFAID._RowKey) | Set-Content -Path .\Temp\PolicyEndpointMFA.json
$caBody = Get-Content (".\Temp\PolicyEndpointMFA.json")

CAWriteLog "INFO" "Provisioning Policy - EndpointMFA"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - EndpointMFA"
        $global:caConfiguration.Policies.EndpointMFA = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - EndpointMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }




#--------------------------------- Connector Mobile Registration  -----------------------------------
((Get-Content -path .\Data\PolicyMobileRegistration.json) -replace 'CARole', $global:caConfiguration.Roles.MobileRegistrationID._RowKey) | Set-Content -Path .\Temp\PolicyMobileRegistration.json
$caBody = Get-Content (".\Temp\PolicyMobileRegistration.json")

CAWriteLog "INFO" "Provisioning Policy - MobileRegistration"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - MobileRegistration"
        $global:caConfiguration.Policies.MobileRegistration = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - MobileRegistration"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }


#--------------------------------- Connector Installer policy  -----------------------------------
((Get-Content -path .\Data\PolicyConnectorInstaller.json) -replace 'CADefaultAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthConnectorInstallerID.Uuid) | Set-Content -Path .\Temp\PolicyConnectorInstaller.json
((Get-Content -path .\Temp\PolicyConnectorInstaller.json) -replace 'CAAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthConnectorInstallerID.Uuid) | Set-Content -Path .\Temp\PolicyConnectorInstaller.json
((Get-Content -path .\Temp\PolicyConnectorInstaller.json) -replace 'CARole', $global:caConfiguration.Roles.ConnectorInstallerID._RowKey) | Set-Content -Path .\Temp\PolicyConnectorInstaller.json
$caBody = Get-Content (".\Temp\PolicyConnectorInstaller.json")

CAWriteLog "INFO" "Provisioning Policy - ConnectorInstaller"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - ConnectorInstaller"
        $global:caConfiguration.Policies.ConnectorInstaller = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - ConnectorInstaller"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }



#--------------------------------- Portal full admin MFA policy  -----------------------------------

((Get-Content -path .\Data\PolicyPortalFullAdminAccessMFA.json) -replace 'CADefaultAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthPortalFullAdminAccessMFAID.Uuid) | Set-Content -Path .\Temp\PolicyPortalFullAdminAccessMFA.json
((Get-Content -path .\Temp\PolicyPortalFullAdminAccessMFA.json) -replace 'CAAuthProfile', $global:caConfiguration.AuthenticationProfiles.AuthPortalFullAdminAccessMFAID.Uuid) | Set-Content -Path .\Temp\PolicyPortalFullAdminAccessMFA.json
((Get-Content -path .\Temp\PolicyPortalFullAdminAccessMFA.json) -replace 'CAUnlockProfile', $global:caConfiguration.AuthenticationProfiles.AuthPortalFullAdminAccessMFAID.Uuid) | Set-Content -Path .\Temp\PolicyPortalFullAdminAccessMFA.json
((Get-Content -path .\Temp\PolicyPortalFullAdminAccessMFA.json) -replace 'CAPassResetProfile', $global:caConfiguration.AuthenticationProfiles.AuthPortalFullAdminAccessMFAID.Uuid) | Set-Content -Path .\Temp\PolicyPortalFullAdminAccessMFA.json
#((Get-Content -path .\Temp\PolicyPortalFullAdminAccessMFA.json) -replace 'CARevStamp', $global:caConfiguration.Policies.RevStamp) | Set-Content -Path .\Temp\PolicyPortalFullAdminAccessMFA.json
$caBody = Get-Content (".\Temp\PolicyPortalFullAdminAccessMFA.json")

CAWriteLog "INFO" "Provisioning Policy - PortalFullAdminAccessMFA"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Policy/SavePolicyBlock3") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned Policy - PortalFullAdminAccessMFA"
        $global:caConfiguration.Policies.PortalFullAdminAccessMFA = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision Policy - PortalFullAdminAccessMFA"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }







#############################################  Add Endpoint MFA role to global permissions ###############################################

((Get-Content -path .\Data\EndpointMFAGlobalPermissions.json) -replace 'EndpointMFAID', $global:caConfiguration.Roles.EndpointMFAID._RowKey) | Set-Content -Path .\Temp\EndpointMFAGlobalPermissions.json
$caBody = Get-Content (".\Temp\EndpointMFAGlobalPermissions.json")

CAWriteLog "INFO" "Provisioning EndpointMFAGlobalPermissions"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Mobile/SetDevicePermissions") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned EndpointMFAGlobalPermissions"
        $global:caConfiguration.GlobalEndpointPermissions = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision EndpointMFAGlobalPermissions"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }



#############################################  Add Endpoint Enrollment Code ###############################################


$caBody = Get-Content (".\Data\EndpointEnrollmentCode.json")

CAWriteLog "INFO" "Provisioning EndpointEnrollmentCode"
$caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/EndpointAgent/AddEnrollmentCode") -ContentType "application/json" -Headers $global:caAuthorizationToken -body $caBody -WebSession $caWebSession
CAWriteLog "INFO" "Response recieved as:"
CAWriteLog "INFO" "$caAPIResponse"
if ($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Successfully provisioned EndpointEnrollmentCode"
#        $global:caConfiguration.GlobalEndpointPermissions = ($caAPIResponse.Result)
    }
    else
    {
        CAWriteLog "ERROR" "Failed to provision EndpointEnrollmentCode"
        if($global:caConfiguration.ContinueOnError -eq "false")  {exit 7}
    }





#################################################################################################################################

$global:caConfiguration | ConvertTo-Json | Set-Content ".\CyberArkIdentityRP.json"

    ################################          logout

    $caQuery = @{}
    $caQuery += @{"User" = $global:caConfiguration.API.Login.Username}
    $caQuery += @{"Version" = "1.0"}
    $caQuery += @{"TenantId" = $global:caConfiguration.API.Login.TenantId}
    $body = $caQuery | ConvertTo-Json
    $caAPIResponse = Invoke-RestMethod -Method POST -Uri ($global:caConfiguration.API.Login.TenantURL+"/Security/Logout") -body $body -ContentType "application/json" -Headers $global:tokenHeader
    if($caAPIResponse.success -eq "True"){
        CAWriteLog "INFO" "Logout succedded !!!"
    }else{
        CAWriteLog "ERROR" "Failed to Logout at Security/Logout !!!"
        exit 99
    }
    

exit 0
