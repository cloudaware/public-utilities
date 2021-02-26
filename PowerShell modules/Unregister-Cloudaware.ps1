# Internal function for logging 
function Write-Log() {
    param (
        [Parameter(Mandatory=$true)]
        [string[]]$message,

        [Parameter(Mandatory=$true)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', $True, $False)]
        [string[]]$messageType,

        [Parameter(Mandatory=$true)]
        [string]$workDir
    )
    # Last command execution status
    $zeroErrStatus = $?
    $logPath = "${workDir}\log.log"
    $date = $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    if ($zeroErrStatus -and ($messageType -ne $False)) {
        Write-Host -NoNewline "[${date}] "
        switch ($messageType)
        {
            'INFO' {Write-Host $message -ForegroundColor 'Cyan'}
            $True {Write-Host $message -ForegroundColor 'Yellow'}
            'WARNING' {Write-Host $message -ForegroundColor 'Magenta'}
            'ERROR' {Write-Host $message -ForegroundColor 'Red'}
        }
    } elseif (-not $zeroErrStatus) {
        Write-Host -NoNewline "[${date}] "
        $messageErr = $Error[0]
        $message = "At line $($MyInvocation.ScriptLineNumber) - ${messageErr}`n"
        Write-Host $message -ForegroundColor 'Red'
    }
    Add-Content -Path $logPath -Value "[${date}] $message"
}

# Internal function for validation of the user parameters
function Confirm-AzureCredentials() {
    param (        
        [Parameter(Mandatory=$true)]
        $workDir
    )
    
    # Checking on whether the user is logged into Azure
    if (-not $(az account list --refresh --query '[].name' --output table 2>$null)) {
        Write-Log -message "Run 'az login' to log in to your account.`n" -messageType 'ERROR' -workDir $workDir
        Return $False
    } else {
        # Collecting all available Subscription Id(s) and the user authentication for Subscription Id(s) in question
        $subscriptionId = $(az account list --query '[].id' --output table)
        $subscriptionId = $subscriptionId[2..$subscriptionId.Length]
        $AccountId = $(az account list --query '[].user.name' --output table)[2]
        $TenantId = $(az account list --query '[].tenantId' --output table)[2]
        $AccessToken = $(az account get-access-token --query 'accessToken') -replace """", ""
        $GraphAccessToken = $(az account get-access-token --resource-type aad-graph --query 'accessToken') -replace """", ""

        # Checking and installing the module AzureAD.Standard.Preview if the condition below is true 
        if (-not (Get-InstalledModule -Name AzureAD.Standard.Preview -RequiredVersion 0.0.0.10 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            Write-Log -message "Loading and exporting the module 'AzureAD.Standard.Preview'." -messageType 'WARNING' -workDir $workDir
            Register-PackageSource -Name PoshTestGallery -Location 'https://www.poshtestgallery.com/api/v2/' -Trusted -ProviderName PowerShellGet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -verbose:$false | Out-Null
            Install-Module -Name AzureAD.Standard.Preview -RequiredVersion 0.0.0.10 -Repository PoshTestGallery -Scope CurrentUser -SkipPublisherCheck -AllowClobber -WarningAction SilentlyContinue -Force -verbose:$false | Out-Null
            Unregister-PSRepository -Name PoshTestGallery
            #$AzureADModuleInstall = $true
        }

        if ($subscriptionId -eq $TenantId) {
            # The condition is true if Subscription Id == Tenant.Id (it means that user does not have any Subscription Id(s))
            Write-Log -message "The user does not have any Subscription(s)." -messageType 'WARNING' -workDir $workDir
            Connect-AzAccount -AccessToken $AccessToken -AccountId $AccountId -GraphAccessToken $GraphAccessToken -Tenant $TenantId -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
            $result = $null
            #$result = $False
        } else {    
            ForEach($subs in $subscriptionId) {
                Connect-AzAccount -Subscription $subs -AccessToken $AccessToken -AccountId $AccountId -GraphAccessToken $GraphAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
            }
            $result = $subscriptionId
        }

        Import-Module AzureAD.Standard.Preview -WarningAction SilentlyContinue -verbose:$false
        # Checking if the user logged into Azure does have the role 'Company Administrator' in Azure AD (or the 'Global administrator' in the new terminology)
        Connect-AzureAD -AccountId $AccountId -AadAccessToken $GraphAccessToken -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | Out-Null
        $role = Get-AzureADDirectoryRole | Where-Object {($_.displayName -eq 'Company Administrator') -or ($_.displayName -eq 'Global Administrator')}
        $objectId = $((az ad signed-in-user show --query objectId) -replace """","")
        if (-not $(Get-AzureADDirectoryRoleMember -ObjectId $role.ObjectId | Where-Object {$_.ObjectId -eq $objectId})){
            Write-Log -message "The user does not have the role 'Global administrator' assigned.`n" -messageType 'ERROR' -workDir $workDir
            $result = $False
        }
        
        return $result
    }
}

# Internal function for deleting roles and policies
function Remove-RolesAndPolicies() {
    param (
        [AllowNull()]
        [Parameter(Mandatory=$true)]
        $removedItem,

        [Parameter(Mandatory=$true)]
        $defaultProfile,

        [Parameter(Mandatory=$true)]
        $servicePrincipalName,

        [Parameter(Mandatory=$true)]
        $verboseEnable,

        [Parameter(Mandatory=$true)]
        $workDir,

        [Parameter(Mandatory=$false)]
        $name,

        [Parameter(Mandatory=$false)]
        $subscription,

        # Switch for removing roles in Subscription Id(s)
        [Parameter(Mandatory=$False)]
        [switch]$subsRoles = $false,

        # Switch for removing roles in Reservation Order Id(s)
        [Parameter(Mandatory=$False)]
        [switch]$orderIdRoles = $false,

        # Switch for removing Key Vaults policy
        [Parameter(Mandatory=$False)]
        [switch]$keyVaultNames = $false
    )

    if ($removedItem) {
        for ($index = 0; $index -lt $removedItem.count; $index++) {
            if ($subsRoles) {
                # Deleting all roles assigned to the AD application in the scope of Subscription Id
                Remove-AzRoleAssignment -servicePrincipalName $servicePrincipalName -RoleDefinitionName $removedItem[$index] -DefaultProfile $defaultProfile -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Write-Log -message "Deleting the role '$($removedItem[$index])' in the scope of Subscription Id '${subscription}'." -messageType $verboseEnable -workDir $workDir
            } elseif ($orderIdRoles) {
                # Deleting all roles assigned to the AD application in the scope of Reservation Order Id
                $removedItem.foreach{
                    ForEach($id in $PSItem.ReservationOrderId) {
                        ForEach($role in $PSItem.ReservationOrderIdRoles) {
                            Remove-AzRoleAssignment -servicePrincipalName $servicePrincipalName -RoleDefinitionName $role -DefaultProfile $defaultProfile -Scope $id -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $zeroErrStatus = $?
                            if ($zeroErrStatus) {
                                Write-Log -message "Deleting the role '${role}' in the scope of Reservation Order Id '$($id.split('/')[-1])'." -messageType $verboseEnable -workDir $workDir
                            }
                        }
                    }
                }

            } elseif ($keyVaultNames) {
                # Deleting the policy assigned to the AD application in the scope of Key Vault(s)
                $accessPolicyAssociated = (Get-AzKeyVault -DefaultProfile $defaultProfile -VaultName $removedItem[$index]).AccessPolicies.DisplayName
                $accessPolicyAssociated.foreach{
                    if ($PSItem.Contains($name)) {
                        Remove-AzKeyVaultAccessPolicy -servicePrincipalName $servicePrincipalName -VaultName $removedItem[$index] -DefaultProfile $defaultProfile -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                        Write-Log -message "The policy 'list' to keys and secrets in Key Vault '$($removedItem[$index])' was deleted." -messageType $verboseEnable -workDir $workDir
                    }
                }
            }
        }
    }
}

# Internal function for checking if the user logged via 'az login' does have the role 'Owner' (RBAC) to Subscription Id(s) and/or Reservation Order Id(s) available to the AD application 
function Confirm-ADAppRoles() {
    param (
        [Parameter(Mandatory=$true)]
        $verificationObject,

        [Parameter(Mandatory=$true)]
        $workDir
    )

    $noErrors = $True
    $wrongSubscriptionRoles = @()
    $wrongReservationOrderIdRoles = @()
    $userPrincipalName = $((Get-AzContext).Account.Id)

    $verificationObject.foreach{
        $scopes = @()
        $scopes += "/subscriptions/$($PSItem.Subscription)"
        $PSItem.ReservationOrder.foreach{
            $scopes += $PSItem.ReservationOrderId
        }

        ForEach($scope in $scopes) {
            # Checking on whether the current user has role 'Owner' (RBAC) or 'AccountAdministrator' (RBAC) in the scope of Subscription Id(s) and Reservation Order Id(s)
            $assignmentRoles = $((Get-AzRoleAssignment -IncludeClassicAdministrators -RoleDefinitionName 'AccountAdministrator' -Scope $scope -ErrorAction SilentlyContinue).SignInName -eq $userPrincipalName) -or `
                               $(Get-AzRoleAssignment -RoleDefinitionName 'Owner' -SignInName $userPrincipalName -Scope $scope -ErrorAction SilentlyContinue)
    
            if (-not $assignmentRoles) {
                if ($scope.Contains('/subscriptions/')) {
                    $wrongSubscriptionRoles += $scope.split('/')[-1]
                } elseif ($scope.Contains('/reservationorders/')) {
                    $wrongReservationOrderIdRoles += $scope.split('/')[-1]
                }
            }
        }
    }

    if ($wrongSubscriptionRoles -or $wrongReservationOrderIdRoles) {
        $noErrors = $False
        if ($wrongSubscriptionRoles) {
            Write-Log -message ("The Subscription Id(s) where the user has not the role 'Owner' (RBAC) assigned to be able to delete roles/policy: ['{0}']" -f ($wrongSubscriptionRoles -Join "', '")) -messageType 'ERROR' -workDir $workDir
        } 
        if ($wrongReservationOrderIdRoles) {
            $wrongReservationOrderIdRoles = $wrongReservationOrderIdRoles | Select-Object -Unique | Where-Object {$_}
            Write-Log -message ("The Reservation Orders ID(s) where the user has not the role 'Owner' (RBAC) assigned to be able to delete roles: ['{0}']" -f ($wrongReservationOrderIdRoles -Join "', '")) -messageType 'ERROR' -workDir $workDir
        }
        Write-Log -message "Fix the errors indicated above and re-run the module.`n" -messageType 'INFO' -workDir $workDir
    }
    Return $noErrors
}


Function Unregister-Cloudaware
{
    <#
        .SYNOPSIS
        Unregister a customer in Cloudaware CMDB

        .DESCRIPTION
        Unregister-Cloudaware is a module to automate the process of user deletion in Cloudaware CMDB.

        .PARAMETER name
        Name of the AD application to be deleted.
        Read more: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-remove-app

        .PARAMETER withoutSubs
        The switch allows to delete the AD application; no roles and/or the policy assigned to the AD application will be unassigned.

        .PARAMETER dryRun
        The switch allows to save the list of parameters and their values that will be used when deleting the AD application during the module Unregister-Cloudaware run.

        .EXAMPLE
        C:\PS> Unregister-Cloudaware -name cloudaware-api-access -dryRun -verbose

        .EXAMPLE
        C:\PS> Unregister-Cloudaware -name cloudaware-api-access -withoutSubs -verbose

        .NOTES
        FunctionName    : Unregister-Cloudaware
        Created by      : Cloudaware
        Version         : 1.0.0
        Date Coded      : 01/01/2021
        Modified by     : 
        Date Modified   : 
        More info       : https://docs.cloudaware.com/

        .INPUTS
        Any PSObjects can be piped in Unregister-Cloudaware.

        .OUTPUTS
        After the module Unregister-Cloudaware run is completed, AD application will be deleted.
        Module Unregister-Cloudaware execution log file is available in '~\cloudaware\log.log'
        
        .LINK
        Company website: https://www.cloudaware.com/
    #>

    [CmdletBinding()]
    Param 
    (
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName=$True)] 
        [ValidateNotNullOrEmpty()] 
        [string]$name,

        [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$True)]
        [switch]$withoutSubs,

        [Parameter(Mandatory=$False, ValueFromPipelineByPropertyName=$True)]
        [switch]$dryRun
    )

    Begin {
        
        # Creating the working directory if it is not present yet
        $workDir = '~\cloudaware'
        if (-not (Test-Path $workDir)) {
            New-Item -Path $workDir -ItemType 'directory' -Force | Out-Null
        }
        # Checking the switch 'Verbose' to ensure that it is set up
        $verboseEnable = $PSBoundParameters.ContainsKey('Verbose')
        # Sleep duration, seconds
        $sleepDuration = 5

        # The variable to save roles and the policy for further usage
        $rolesAndPolicyList = @()

        # Checking on whether the module 'Az.Reservations' is installed
        if (-not (Get-InstalledModule -Name Az.Reservations -RequiredVersion 0.9.0 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
            Write-Log -message "Loading and exporting the module 'Az.Reservations'." -messageType 'WARNING' -workDir $workDir
            Install-Module -Name Az.Reservations -RequiredVersion 0.9.0 -Scope CurrentUser -Repository PSGallery -SkipPublisherCheck -AllowClobber -WarningAction SilentlyContinue -Force -verbose:$false | Out-Null
        }
    }
    Process {      
        if ($dryRun) {
            Write-Log -message "The mode to save roles and Key Vault name(s) with the policy 'list' for the AD application during the current module run." -messageType $verboseEnable -workDir $workDir
        } else {
            Write-Log -message "Start of the AD application deletion." -messageType 'INFO' -workDir $workDir
        }

        Write-Log -message "Getting Subscription Id(s)." -messageType $verboseEnable -workDir $workDir

        # Checking the variable '$subscriptionId'
        if (($subscriptionId = $(Confirm-AzureCredentials -workDir $workDir)) -eq $False) {
            # Collecting all available Subscription Id(s) and the user authentication for Subscription Id(s) in question, if the condition below is $False
            Return

        } elseif ((-not $subscriptionId) -and (-not $withoutSubs)) {
            # If the user does not have any Subscription Id(s) and the switch '-withoutSubs' is not present - the module run will be terminated
            Write-Log -message "The user does not have any Subscription Id(s) to unassign roles and/or the policy that are assigned to the AD application '${name}'.`n" -messageType 'ERROR' -workDir $workDir
            Return

        } elseif (-not ($applicationId = (Get-AzADApplication -DisplayName $name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ApplicationId)) {
            # Collecting the AD application name
            $count = 1
            while(($null -eq $applicationId) -and ($count -lt 3)){
                Start-Sleep -s $($sleepDuration * $count)
                $applicationId = $((Get-AzADApplication -DisplayName $name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ApplicationId)
                $count++
            }
            if (-not $applicationId) {
                Write-Log -message "The AD application '${name}' does not exist.`n" -messageType 'ERROR' -workDir $workDir
                Return
            }

        } elseif (-not ([string[]]$servicePrincipalNames = (Get-AzADServicePrincipal -ApplicationId $applicationId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ServicePrincipalNames)) {
            # Collecting the Service Principal Name
            $count = 1
            while(($null -eq $servicePrincipalNames) -and ($count -lt 3)){
                Start-Sleep -s $($sleepDuration * $count)
                [string[]]$servicePrincipalNames = $((Get-AzADServicePrincipal -ApplicationId $applicationId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ServicePrincipalNames)
                Write-Host $count
                $count++
            }
            if (-not $servicePrincipalNames) {
                Write-Log -message "An error occurred while extracting Service Principal Name(s).`n" -messageType 'ERROR' -workDir $workDir
                Return
            }
        }

        # The value of User Principal Name for the current user
        $userPrincipalName = $((Get-AzContext).Account.Id)

        if ($subscriptionId) {
            ForEach($servicePrincipalName in $servicePrincipalNames) {
                Write-Log -message "Collecting roles and the policy assigned to the AD application '${name}' (Service Principal Name is '${servicePrincipalName}')." -messageType 'INFO' -workDir $workDir
                ForEach($subs in $subscriptionId) {
                    # Collecting the default profile
                    $defaultProfile = ((Get-AzContext -ListAvailable) | Where-Object { $_.Subscription.Id -Match $subs -and $_.Account.Id -Match $userPrincipalName})

                    # Collecting the Role DefinitionName(s) for the current Subscription Id
                    [string[]]$subsRolesList = (Get-AzRoleAssignment -DefaultProfile $defaultProfile `
                                                                     -Scope "/subscriptions/${subs}" `
                                                                     -servicePrincipalName $servicePrincipalName `
                                                                     -ErrorAction SilentlyContinue `
                                                                     -WarningAction SilentlyContinue).RoleDefinitionName

                    $ReservationOrder = @()
                    # Collecting the Reservation Order Id(s) for the current Subscription Id
                    [string[]]$orderId = (Get-AzReservationOrderId -SubscriptionId $subs -ErrorAction SilentlyContinue).AppliedReservationOrderId
                    $orderId.ForEach{
                        $reservationHash = @{}
                        $reservationHash.Add('ReservationOrderId', $PSItem)
                        $reservationHash.Add('ReservationOrderIdRoles', $(Get-AzRoleAssignment -DefaultProfile $defaultProfile -Scope $PSItem -servicePrincipalName $servicePrincipalName -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).RoleDefinitionName)
                        $ReservationOrder += $reservationHash
                    }
                    
                    # Key Vault name(s) where we will search the policy associated with AD application that we will delete
                    [string[]]$keyVaultNamesList = (Get-AzKeyVault -DefaultProfile $defaultProfile).VaultName
                    
                    $rolesAndPolicyList += [ordered]@{
                        'ServicePrincipalName' = $servicePrincipalName
                        'Subscription' = $subs
                        'DefaultProfile' = $defaultProfile
                        'SubscriptionsRoles' = $subsRolesList
                        'ReservationOrder' = $ReservationOrder
                        'KeyVaultNames' = $keyVaultNamesList
                    }
                }
            }
        }

        if (-not $withoutSubs) {
            Write-Log -message "Checking if the user logged via 'az login' does have the role 'Owner' (RBAC) to Subscription Id(s) and/or Reservation Order Id(s) available to the AD application." -messageType 'INFO' -workDir $workDir
            # Checking on whether the user who runs the module does have the role 'Owner' (RBAC) to Subscription Id(s) and Reservation Order Id(s)
            if ((Confirm-ADAppRoles -verificationObject $rolesAndPolicyList -workDir $workDir) -eq $False) { Return }
        }

        if ($dryRun) {
            if ($subscriptionId) {
                # Saving roles and Key Vaults name(s) for each Subscription Id(s) into JSON file
                $rolesAndPolicyJSON = "${workDir}\dryRunToDeleteApp_$($userPrincipalName.split('@')[0])_${name}.json"
                # Deleting the field 'DefaultProfile' (this field is not informative in the 'dryRun' mode)
                $rolesAndPolicyList.foreach{$PSItem.Remove("DefaultProfile")}
                # Saving Reservation Order Id(s) into JSON file
                $rolesAndPolicyList.foreach{
                    $PSItem.ReservationOrder.foreach{
                        $PSItem.ReservationOrderId = $PSItem.ReservationOrderId.split('/')[-1]
                    }
                }
                $rolesAndPolicyList | ConvertTO-Json -Depth 10 | Out-File $rolesAndPolicyJSON
                Write-Log -message ("The JSON file with roles and Key Vaults name(s) that will be unassigned from the AD application '${name}' is saved in: '${rolesAndPolicyJSON}'.`n") -messageType 'INFO' -workDir $workDir
            } else {
                Write-Log -message "The user does not have any of Subscription Id(s) available to save roles and the policy that are associated with the AD application '${name}'.`n" -messageType 'INFO' -workDir $workDir
            }
        } else {

            if (-not $withoutSubs) {
                # Deleting the roles that are associated with Subscription Id(s)
                Write-Log -message "Searching for the roles that are associated with Subscription Id(s)." -messageType 'INFO' -workDir $workDir
                $rolesAndPolicyList.foreach{
                    Remove-RolesAndPolicies -removedItem $PSItem.SubscriptionsRoles `
                                            -defaultProfile $PSItem.DefaultProfile `
                                            -servicePrincipalName $PSItem.ServicePrincipalName `
                                            -subscription $PSItem.Subscription `
                                            -verboseEnable $verboseEnable `
                                            -workDir $workDir `
                                            -subsRoles
                }
                # Deleting the roles that are associated with Reservation Order Id(s)
                Write-Log -message "Searching for the roles that are associated with Reservation Order Id(s)." -messageType 'INFO' -workDir $workDir
                $rolesAndPolicyList.foreach{
                    Remove-RolesAndPolicies -removedItem $PSItem.ReservationOrder `
                                            -defaultProfile $PSItem.DefaultProfile `
                                            -servicePrincipalName $PSItem.ServicePrincipalName `
                                            -verboseEnable $verboseEnable `
                                            -workDir $workDir `
                                            -orderIdRoles
                }
                # Deleting the policy assigned to Service Principal Name in Key Vault name(s) 
                Write-Log -message "Searching for the policy 'list' to keys and secrets assigned to Service Principal Name in Key Vault(s)." -messageType 'INFO' -workDir $workDir
                $rolesAndPolicyList.foreach{                            
                    Remove-RolesAndPolicies -removedItem $PSItem.KeyVaultNames `
                                            -defaultProfile $PSItem.DefaultProfile `
                                            -name $name `
                                            -servicePrincipalName $PSItem.ServicePrincipalName `
                                            -verboseEnable $verboseEnable `
                                            -workDir $workDir `
                                            -keyVaultNames
                }
            }

            # Deleting the AD application
            Remove-AzADApplication -DisplayName $name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Force

            $msg = "The AD application '${name}' has been deleted"
            if (-not $subscriptionId) {	$msg = $msg + ", no roles and the policy are unassigned" }
            Write-Log -message "${msg}.`n" -messageType 'INFO' -workDir $workDir
        }
    }
    End {}
}
