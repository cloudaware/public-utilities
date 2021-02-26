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
    $logPath = "${workDir}\log.log"
    $zeroErrStatus = $?
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

# Internal function for validation of the following parameters: $name, $credentialExpiration, $certificateFile, $redirectUri, $withSubscriptionRole, $withKeyVaultPolicies, $withKubernetesRole, $withKubernetesRole
Function Confirm-Properties {
    Param(
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$true)]
        # The parameter to be validated
        $parameterValidation,

        [Parameter(Mandatory=$false)]
        [string[]]$subscriptionId,

        [Parameter(Mandatory=$false)]
        [string]$userPrincipalName,

        [Parameter(Mandatory=$true)]
        [string]$workDir,

        [Parameter(Mandatory=$False)]
        [switch]$validatingName=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingCredentialExpiration=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingCertificateFile=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingRedirectUri=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingWithSubscriptionRole=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingWithKeyVaultPolicies=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingWithKubernetesRole=$False,
        [Parameter(Mandatory=$False)]
        [switch]$validatingWithReservationRole=$False
    )

    if ($validatingName -or $validatingCredentialExpiration -or $validatingCertificateFile -or $validatingRedirectUri) {
        # Validation of $name, $credentialExpiration, $certificateFile, $redirectUri
        if ($validatingName -and ($parameterValidation -isnot [System.String])) {
            $unavailableParam = $parameterValidation
        } elseif ($validatingCredentialExpiration -and -not(($parameterValidation.GetType().Name).Contains('Int'))) {
            $unavailableParam = $parameterValidation
        } elseif ($validatingCertificateFile -and (-not (Test-Path -Path $parameterValidation -ErrorAction SilentlyContinue))) {
            $unavailableParam = $parameterValidation
        } elseif ($validatingRedirectUri -and ($parameterValidation -isnot [System.String])) {
            $unavailableParam = $parameterValidation
        }
    } elseif ($validatingWithSubscriptionRole -or $validatingWithKeyVaultPolicies -or $validatingWithKubernetesRole -or $validatingWithReservationRole) {
        # Validation of $withSubscriptionRole, $withKubernetesRole, $withKeyVaultPolicies, $withReservationRole
        # If $null - no action required
        if ($null -eq $parameterValidation) {
            $checkResult = $parameterValidation
        } else {
            # Tracking the presence of a value/array
            # Filtering out the value/array to ensure that it is not $null
            [string[]]$parameterValidation = $parameterValidation | Select-Object -Unique | Where-Object {$_}
            # Tracking the filtered value/array. If $null or 'all', all values available to the user to be used
            if (($null -eq $parameterValidation) -or ($parameterValidation.Count -eq 1 -and $parameterValidation.ToLower() -eq 'all')) {
                $checkResult = $true
            } else {
                # Using specified value(s) of the parameter
                $checkResult = $parameterValidation
            }
        }

        #################################################################### Collection $parameterValidation ####################################################################
        if ($checkResult -is [Bool]) {
            if ($validatingWithSubscriptionRole -or $validatingWithKubernetesRole) {
                # Checking all available Subscription Id(s) to ensure that the role 'Owner' is assigned, if the condition above is true
                [string[]]$parameterValidation = $subscriptionId
            } elseif ($validatingWithKeyVaultPolicies) {
                # Checking all available key vaults for the policy 'list' to be added to keys and secrets, if the condition above is true
                [string[]]$parameterValidation = @()
                ForEach($subs in $subscriptionId) {
                    $defaultProfile = ((Get-AzContext -ListAvailable) | Where-Object { ($_.Subscription.Id -Match $subs) -and ($_.Account.Id -Match $userPrincipalName)})
                    $parameterValidation += ((Get-AzKeyVault -DefaultProfile $defaultProfile).VaultName)
                }
            } elseif ($validatingWithReservationRole) {
                # Preparing the validation of Reservation Order id(s) to run, if the condition above is true
                if (-not (Get-InstalledModule -Name Az.Reservations -RequiredVersion 0.9.0 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)) {
                    Write-Log -message "Loading and exporting the module 'Az.Reservations'." -messageType 'WARNING' -workDir $workDir
                    Install-Module -Name Az.Reservations -RequiredVersion 0.9.0 -Scope CurrentUser -Repository PSGallery -SkipPublisherCheck -AllowClobber -WarningAction SilentlyContinue -Force -verbose:$false | Out-Null
                    #$AzReservationsModuleInstall = $true
                }
                # Checking all available Reservation Order id(s) to ensure that the role 'Owner' is assigned, if the condition above is true
                $parameterValidation = @()
                ForEach($subs in $subscriptionId) {
                    $parameterValidation += $((Get-AzReservationOrderId -SubscriptionId $subs -ErrorAction SilentlyContinue).AppliedReservationOrderId)
                }
                # Deleting $null and empty
                $parameterValidation = $parameterValidation | Select-Object -Unique | Where-Object {$_}
                if (-not $parameterValidation) {$notAvailableReservationOrderIds = $True}
            }
        } else {
            [string[]]$parameterValidation = $checkResult
            if ($validatingWithReservationRole -and $parameterValidation) {
                # Creating the full path to each Reservation Order Id(s), if the condition above is true
                (0..($parameterValidation.length - 1) ) | foreach-object {$parameterValidation[$_] = "/providers/Microsoft.Capacity/reservationorders/$($parameterValidation[$_])" }
            }
        }

        #################################################################### Validation $parameterValidation ####################################################################
        $unavailableParam = @()
        if ($validatingWithSubscriptionRole -or $validatingWithKubernetesRole -or $validatingWithReservationRole) {
            # Validating Subscription Id(s) and Reservation Order id(s) to ensure that the role 'Owner' is assigned, if the condition above is true
            $notSharedReservationOrderIds = @()
            if ($notAvailableReservationOrderIds) {
                $notAvailableReservationOrderIds
            } else {
                $parameterValidation.Foreach{
                    if ($validatingWithReservationRole) {
                        $Scope = $PSItem
                    } else {
                        $Scope = "/subscriptions/${PSItem}"
                    }
                    $assignmentID = $((Get-AzRoleAssignment -IncludeClassicAdministrators -RoleDefinitionName 'AccountAdministrator' -Scope $Scope -ErrorAction SilentlyContinue).SignInName -eq $userPrincipalName) -or `
                                    $(Get-AzRoleAssignment -RoleDefinitionName 'Owner' -SignInName $userPrincipalName -Scope $Scope -ErrorAction SilentlyContinue)
                    if (-not $assignmentID) {
                        $unavailableParam += $PSItem
                    } elseif ($validatingWithReservationRole -and $assignmentID) {
                        # The condition for '$withReservationRole' if the condition above is true
                        if ((Get-AzReservation -ReservationOrderId $($PSItem.split('/')[-1]) -ErrorAction SilentlyContinue).AppliedScopeType -ne 'Shared') {
                            $zeroErrStatus = $?
                            if ($zeroErrStatus) {
                                $notSharedReservationOrderIds += $PSItem
                            }
                        }
                    }
                }
            }
        # This part of the module will be updated when Key Vault Reader (preview) will be stable
        # https://docs.microsoft.com/en-us/azure/key-vault/general/rbac-guide
        } elseif ($validatingWithKeyVaultPolicies) {

            $notSubscriptionOwnerForKeyVault = @()
            # Validating Subscription Id(s) to ensure that the role 'Owner' is assigned
            ForEach($subs in $subscriptionId) {
                $Scope = "/subscriptions/${subs}"
                $assignmentID = $((Get-AzRoleAssignment -IncludeClassicAdministrators -RoleDefinitionName 'AccountAdministrator' -Scope $Scope -ErrorAction SilentlyContinue).SignInName -eq $userPrincipalName) -or `
                                $(Get-AzRoleAssignment -RoleDefinitionName 'Owner' -SignInName $userPrincipalName -Scope $Scope -ErrorAction SilentlyContinue)
                if (-not $assignmentID) {
                    $notSubscriptionOwnerForKeyVault += $subs
                }
            }
            if (-not $notSubscriptionOwnerForKeyVault) {
                # Validation of key vaults names, if the condition above is true
                $parameterValidation.Foreach{
                    $coincident = $False
                    ForEach($subs in $subscriptionId) {
                        $defaultProfile = ((Get-AzContext -ListAvailable) | Where-Object { ($_.Subscription.Id -Match $subs) -and ($_.Account.Id -Match $userPrincipalName)})
                        if (Get-AzKeyVault -VaultName $PSItem -DefaultProfile $defaultProfile -ErrorAction SilentlyContinue){
                            $coincident = $True 
                            Break
                        }
                    }
                    if (-not $coincident) {
                        $unavailableParam += $PSItem
                    }
                }
            }
        }
    } else {
        # Validation of passed on parameter
        Write-Log -message "The parameter '${parameterValidation}' is not the subject of validation." -messageType 'WARNING' -workDir $workDir
    }
    #################################################################### Errors ####################################################################
       
    if ($unavailableParam -or $notSharedReservationOrderIds -or $notAvailableReservationOrderIds -or $notSubscriptionOwnerForKeyVault) {
        if ($unavailableParam) {
            if ($validatingName) {
                $mess = "The value of the variable 'name' does not correspond to the data type [String]: '${unavailableParam}'"
            } elseif ($validatingCredentialExpiration) {
                $mess = "The value of the variable 'credentialExpiration' does not correspond to the data type [Int]: '${unavailableParam}'"
            } elseif ($validatingCertificateFile) {
                $mess = "The path in the variable 'certificateFile' is not correct: '${unavailableParam}'"
            } elseif ($validatingRedirectUri) {
                $mess = "The value of the variable 'redirectUri' does not correspond to the data type [String]: '${unavailableParam}'"
            } elseif ($validatingWithSubscriptionRole) {
                $mess = ("Subscription Id(s) from 'withSubscriptionRole', where the user does not have the role 'Owner' (RBAC) assigned: ['{0}']" -f ($unavailableParam -Join "', '"))
            } elseif ($validatingWithKubernetesRole) {
                $mess = ("Subscription Id(s) from 'withKubernetesRole', where the user does not have the role 'Owner' (RBAC) assigned: ['{0}']" -f ($unavailableParam -Join "', '"))
            } elseif ($validatingWithReservationRole) {
                $mess = ("Reservation Order Id(s), where the user does not have the role 'Owner' (RBAC) assigned: ['{0}']" -f ($unavailableParam.split('/providers/Microsoft.Capacity/reservationorders/', [System.StringSplitOptions]::RemoveEmptyEntries) -Join "', '"))
            } elseif ($validatingWithKeyVaultPolicies) {
                $mess = ("Key Vault name(s) that are not associated with any of the available Subscription Id(s): ['{0}']" -f ($unavailableParam -Join "', '"))
            }
        } elseif ($notAvailableReservationOrderIds) {
            $mess = ("Reservation Order Id(s) were not discovered.")
        } elseif ($notSharedReservationOrderIds) {
            $mess = ("Reservation Order Id(s) where the scope is not set up as 'Shared': ['{0}']" -f ($notSharedReservationOrderIds.split('/providers/Microsoft.Capacity/reservationorders/', [System.StringSplitOptions]::RemoveEmptyEntries) -Join "', '"))
        } elseif ($notSubscriptionOwnerForKeyVault) {
            $mess = ("Subscription Id(s) from 'withKeyVaultPolicies', where the user does not have the role 'Owner' (RBAC) assigned: ['{0}']" -f ($notSubscriptionOwnerForKeyVault -Join "', '"))
        }

        # Содержание тела уведомления в зависимости от условия (что описаны выше)
        Write-Log -message $mess -messageType 'ERROR' -workDir $workDir
        Write-Log -message "Fix the errors indicated above and re-run the module.`n" -messageType 'INFO' -workDir $workDir

        $result = $False
    } else {
        $result = $parameterValidation
    }
    Return $result
}

# Internal function for generating the template file: "~\cloudaware\template.json"  
function Get-Template() {
    param (
        [Parameter(Mandatory=$true)]
        $workDir
    )
    [ordered]@{
        name = 'cloudaware-api-access'
        credentialExpiration = 1
        certificateFile = './cert.pem'
        redirectUri = 'https://cloudaware-api-access.com'
        withSubscriptionRole = 'all'
        withKeyVaultPolicies = 'all'
        withKubernetesRole = 'all'
        withReservationRole = 'all'
    } | ConvertTO-Json | Out-File "${workDir}\template.json"
    Write-Log -message "The template is saved in '${workDir}\template.json' file.`n" -messageType 'WARNING' -workDir $workDir
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
            # The condition is true if Subscription Id == Tenant.Id (it means that user doesn't have any Subscription Id(s))
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

# Internal function for reading parameters from the file
function Get-ParametersFromFile() {
    param ( 
        [Parameter(Mandatory=$true)]
        $fromTemplate,
        [Parameter(Mandatory=$true)]
        $workDir
    )
    Write-Log -message "Reading parameters from the file '${fromTemplate}'." -messageType $verboseEnable -workDir $workDir
    try {
        $json = Get-Content -Raw $fromTemplate -ErrorAction Stop | ConvertFrom-Json
        return $json
    } catch {
        $msg = $Error[0].Exception.Message
        Write-Log -message "${msg}.`n" -messageType 'ERROR' -workDir $workDir
        Return $False
    }
}

# Internal function for creating a new AD application
function Request-Aplication() {
    param ( 
        [Parameter(Mandatory=$true)]
        $name,

        [Parameter(Mandatory=$true)]
        $credentialExpiration,

        [AllowNull()]
        [AllowEmptyString()]
        [Parameter(Mandatory=$false)]
        $certificateFile,

        [Parameter(Mandatory=$false)]
        $createKeyAndSertificate,

        [AllowNull()]
        [AllowEmptyString()]
        [Parameter(Mandatory=$false)]
        $redirectUri,

        [Parameter(Mandatory=$true)]
        $userPrincipalName,

        [Parameter(Mandatory=$true)]
        $sleepDuration,

        [Parameter(Mandatory=$true)]
        $workDir,

        [Parameter(Mandatory=$true)]
        $verboseEnable
    )
    # Registering a new AD application
    Do {
        if (-not $appExist) {
            if ($redirectUri) {
                if (-not $(az ad app create --display-name $name --reply-urls $redirectUri --available-to-other-tenants True 2>$null )){
                    Write-Log -message "Invalid value specified for property 'replyUrls' of resource 'Application': '${redirectUri}'. Detailed information: 'https://docs.microsoft.com/en-us/azure/active-directory/develop/reply-url'`n" -messageType 'ERROR' -workDir $workDir
                    Return $result = $False
                }
            } else {az ad app create --display-name $name --available-to-other-tenants True | Out-Null}
            $appExist = $true
        } elseif ($appExist) {
            Start-Sleep -s $sleepDuration
            if ($null -ne (Get-AzADApplication -DisplayName $name)) {
                $redirectUri ? (Write-Log -message "The AD application '${name}' with Redirect URI '${redirectUri}' is created." -messageType $verboseEnable -workDir $workDir) : `
                               (Write-Log -message "The AD application '${name}' is created." -messageType $verboseEnable -workDir $workDir)
                
                # Getting the Application Id
                $count = 1
                while($null -eq $appId){
                    Start-Sleep -s $($sleepDuration * $count)
                    $appId = $((Get-AzADApplication -DisplayName $name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).ApplicationId)
                    $count++
                }
                # Getting the Tenant Id
                $tenantId = $((Get-AzContext).Tenant.Id)

                if ($certificateFile -or $createKeyAndSertificate) {
                    # Creating a secret or a certificate if condition above is true
                    if ($certificateFile) {
                        # Adding the existing certificate
                        if (-not $(az ad app credential reset --id $appId --cert "@${certificateFile}" --append --years $credentialExpiration --only-show-errors 2>$null )) {
                            Write-Log -message "ValidationError: Incorrect padding. Detailed information: 'https://docs.microsoft.com/en-us/cli/azure/ad/app/credential?view=azure-cli-latest#az_ad_app_credential_reset'`n" -messageType 'ERROR' -workDir $workDir
                            az ad app delete --id $appId
                            Return $result = $False
                        }
                    } elseif ($createKeyAndSertificate) {
                        # Generating the certificate
                        if (-not ($pathWithCertAndPrivateKey = $(az ad app credential reset --id $appId --create-cert --append --years $credentialExpiration --only-show-errors --query 'fileWithCertAndPrivateKey') -replace """", "") 2>$null) {
                            Write-Log -message "Deleting the AD application '${name}': an error occurred while creating certificates.`n" -messageType 'ERROR' -workDir $workDir
                            az ad app delete --id $appId
                            Return $result = $False
                        }
                        $fileWithCertAndPrivateKey = Get-Content -Path $pathWithCertAndPrivateKey -Raw

                        $fileWithCertAndPrivateKey -cmatch "(?<key>-----BEGIN PRIVATE KEY-----[\s\S]*-----END PRIVATE KEY-----)" | Out-Null
                        $Matches.key | Out-File "${workDir}\$($userPrincipalName.split('@')[0])_${appId}.key"
                        Write-Log -message "The path to the key: '${workDir}\$($userPrincipalName.split('@')[0])_${appId}.key'" -messageType 'WARNING' -workDir $workDir

                        $fileWithCertAndPrivateKey -cmatch "(?<cert>-----BEGIN CERTIFICATE-----[\s\S]*-----END CERTIFICATE-----)" | Out-Null
                        $Matches.cert | Out-File "${workDir}\$($userPrincipalName.split('@')[0])_${appId}.cert"
                        Write-Log -message "The path to the certificate: '${workDir}\$($userPrincipalName.split('@')[0])_${appId}.cert'" -messageType 'WARNING' -workDir $workDir
                        
                        Remove-Item -Path $pathWithCertAndPrivateKey -Force
                    }
                } elseif ((-not $certificateFile) -and (-not $createKeyAndSertificate)) {
                    # Creating a password if the condition above is true
                    $pass = $(az ad app credential reset --id $appId --append --years $credentialExpiration --query 'password' --only-show-errors) -replace """", ""
                }

                # Getting the Credential Id
                $count = 1
                while($null -eq $credentialId){
                    $credentialId = (Get-AzADAppCredential -ApplicationId $appId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).KeyId
                    Start-Sleep -s $($sleepDuration * $count)
                    $count++
                }

                # Create the Service Principal for the AD application
                New-AzADServicePrincipal -ApplicationId $appId -SkipAssignment -verbose:$false -ErrorAction SilentlyContinue | Out-Null
                $appCheck = $true

                ($certificateFile -or $createKeyAndSertificate) ? (Write-Log -message "The credential id of the created certificate: '${credentialId}'." -messageType $verboseEnable -workDir $workDir) : `
                                                                  (Write-Log -message "The credential id of the created client secret: '${credentialId}'." -messageType $verboseEnable -workDir $workDir)
            }
        }
    }
    Until($appCheck)

    $result = [ordered]@{Name = $name
                         Active_Directory_ID = $tenantId
                         Application_ID = $appId
                         Client_Secret = $pass
                         Credential_ID = $credentialId
    }

    return $result
}

# Internal function for assigning API permissions to the created AD application
function Add-ApiPermissions() {
    param ( 
        [Parameter(Mandatory=$true)]
        $name,

        [Parameter(Mandatory=$true)]
        $appId,

        [Parameter(Mandatory=$true)]
        $userPrincipalName,

        [Parameter(Mandatory=$true)]
        $sleepDuration,

        [Parameter(Mandatory=$true)]
        $workDir,

        [Parameter(Mandatory=$true)]
        $verboseEnable
    )

    # APIs permissions
    $apiPermission = [ordered]@{
        # Azure Service Management:
        ### Delegated 'Access Azure Service Management as organization users (preview)'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = @('41094075-9dad-400e-a0bd-54e686782033=Scope')
        # Microsoft Graph:
        ### Delegated 'Read directory data',  Application 'Read directory data', Delegated 'Sign in and read user profile'
        '00000003-0000-0000-c000-000000000000' = @('06da0dbc-49e2-44d2-8312-53f166ab848a=Scope', '7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role', 'e1fe6dd8-ba31-4d61-89e7-88639da4683d=Scope')
        # Azure Active Directory Graph
        ### Delegated 'Read directory data', Application 'Read directory data', Delegated 'Sign in and read user profile'
        '00000002-0000-0000-c000-000000000000' = @('5778995a-e1bf-45b8-affa-663a9f3f4d04=Scope', '5778995a-e1bf-45b8-affa-663a9f3f4d04=Role', '311a71cc-e848-46a1-bdf8-97ff7156d8e6=Scope')
    } 
    # Microsoft Graph
    # Azure Active Directory Graph
    # Azure Service Management
    # Assigning APIs through admin-consent
    for ($index = 0; $index -le 1; $index++) {
        if ($index -eq 0) {
            # Assigning API permissions
            $conditions = @()
            foreach ($api in $apiPermission.keys) {
                az ad app permission add --id $appId --api $api --api-permissions $apiPermission[$api] --only-show-errors
                $conditions += $apiPermission[$api] -replace "=.*", ''
                Start-Sleep -s $sleepDuration
            }
        } else {
            # Approving APIs through admin-consent
            Start-Sleep -s $sleepDuration
            az ad app permission admin-consent --id $appId
            $conditions = @('Windows Azure Active Directory', 'Windows Azure Service Management API', 'Microsoft Graph')
        }
        # Checking on whether API permissions are assigned and APIs are approved through admin-consent successfully
        $result = $false
        $numberAttempts = 1
        Do {
            Start-Sleep -s $($sleepDuration * $numberAttempts)
            if ($index -eq 0) {
                # Getting the list of API permissions assigned
                $resource = $(az ad app permission list --id $appId --query '[].resourceAccess[].id' --output table)
                Start-Sleep -s $sleepDuration
                $resourceAppId = $(az ad app permission list --id $appId --query '[].resourceAppId' --output table)
            } else {
                # Getting the list of APIs approved through admin-consent
                $resource = $(az ad app permission list-grants --id $appId --show-resource-name --query '[].resourceDisplayName' --output table)
            }
            $сoincidentСonditions = 0
            for ($i = 0; $i -lt $conditions.count; $i++) {
                if ($resource -and $resource.Contains($conditions[$i])) {
                    $сoincidentСonditions++
                }
            }
            if ($numberAttempts -eq 6) {
                # Deleting the AD application if API permissions were not assigned correctly
                Remove-Item -Path "${workDir}\$($userPrincipalName.split('@')[0])_${appId}*" -Force
                az ad app delete --id $appId
                Write-Log -message "Deleting the AD application '${name}': API permissions were not assigned correctly.`n" -messageType 'ERROR' -workDir $workDir
                Return $False
            } elseif (($numberAttempts -eq 3) -or ($numberAttempts -eq 5)) {
                if ($index -eq 0) {
                    foreach ($api in $apiPermission.keys) {
                        # Re-assigning API permissions (if the intial command didn't result as expected)
                        if (-not $resourceAppId.Contains($api)) {
                            az ad app permission add --id $appId --api $api --api-permissions $apiPermission[$api] --only-show-errors
                            Start-Sleep -s $sleepDuration
                        }
                    }
                } else {
                    # Re-approve APIs through admin-consent (if the intial command didn't result as expected)
                    az ad app permission admin-consent --id $appId 
                }
            }
            $numberAttempts++
            $сoincidentСonditions -eq $conditions.count ? $($result = $true) : (Write-Log -message 'Waiting for API to be set up...' -messageType $verboseEnable -workDir $workDir)
        }
        Until($result)
    }
}

# Internal function for configuring roles and policies
function Add-RolesAndPolitics() {
    param (
        [Parameter(Mandatory=$true)]
        $name,

        [Parameter(Mandatory=$true)]
        $appId,

        [AllowNull()]
        [Parameter(Mandatory=$true)]
        $properties,

        [Parameter(Mandatory=$false)]
        $subscriptionId,

        [Parameter(Mandatory=$false)]
        $userPrincipalName,

        [Parameter(Mandatory=$true)]
        $workDir,

        [Parameter(Mandatory=$true)]
        $verboseEnable,

        [Parameter(Mandatory=$false)]
        [switch]$assignToSubscriptionRole = $false,

        [Parameter(Mandatory=$false)]
        [switch]$assignToKubernetesRole = $false,

        [Parameter(Mandatory=$false)]
        [switch]$assignToReservationRole = $false,

        [Parameter(Mandatory=$false)]
        [switch]$assignToKeyVaultPolicy = $false
    )
    $properties.Foreach{
        if ($assignToSubscriptionRole -or $assignToKubernetesRole -or $assignToReservationRole) {
            if ($assignToSubscriptionRole) {
                # The role 'Reader' for Subscription Id(s) discovery in Cloudaware CMDB
                $RoleDefinitionName = 'Reader'
                $Scope = "/subscriptions/${PSItem}"
                $Description = "The role 'Reader' is assigned to the AD application '${name}' in the scope of the Subscription Id(s) '${PSItem}'"
            } elseif ($assignToKubernetesRole) {
                # The role 'Azure Kubernetes Service Cluster Admin Role' for Azure Kubernetes Service discovery in Cloudaware CMDB
                $RoleDefinitionName = 'Azure Kubernetes Service Cluster Admin Role'
                $Scope = "/subscriptions/${PSItem}"
                $Description = "The role 'Azure Kubernetes Service Cluster Admin Role' is assigned to the AD application '${name}' in the scope of the Subscription Id(s) '${PSItem}'"
            } elseif ($assignToReservationRole) {
                # The role 'Reader' for Reservation Order id(s)) discovery in Cloudaware CMDB
                $RoleDefinitionName = 'Reader'
                $Scope = $PSItem
                $ID = $PSItem.split('/')[-1]
                $Description = "The role 'Reader' is assigned to the AD application '${name}' in the scope of Azure Reservation Order Id(s) '${ID}'"
            }
            # Assigning the role
            New-AzRoleAssignment -ApplicationId $appId -RoleDefinitionName $RoleDefinitionName -Scope $Scope -Description $Description -ErrorAction SilentlyContinue | Out-Null
            Write-Log -message $Description -messageType $verboseEnable -workDir $workDir
        } elseif ($assignToKeyVaultPolicy) {
            # Assigning the policy 'list' for keys and secrets in Key Vaults
            ForEach($subs in $subscriptionId) {
                $defaultProfile = ((Get-AzContext -ListAvailable) | Where-Object { $_.Subscription.Id -Match $subs -and $_.Account.Id -Match $userPrincipalName})
                if (Set-AzKeyVaultAccessPolicy -VaultName $PSItem -DefaultProfile $defaultProfile -PermissionsToKey 'list' -PermissionsToSecrets 'list' -ServicePrincipalName $app.Application_ID -ErrorAction SilentlyContinue | Out-Null) {
                    Break
                }
            }
            Write-Log -message "The policy 'list' for keys and secrets in Key Vault '${PSItem}' is assigned to the AD application '${name}'." -messageType $verboseEnable -workDir $workDir
        }
    }
}

# Internal function for saving and outputting the app data required for the integration with Cloudaware CMDB
function Get-DataIntegration() {
    param ( 
        [Parameter(Mandatory=$true)]
        $app,
        [Parameter(Mandatory=$true)]
        $userPrincipalName,
        [Parameter(Mandatory=$true)]
        $workDir
    )
    # Outputting the AD application data to the console
    Write-Host -ForegroundColor Green -Object ("
    Name                : {0}
    Active Directory ID : {1}
    Application ID      : {2}
    Client Secret       : {3}
    Credential ID       : {4}`n" -f $app.Name, $app.Active_Directory_ID, $app.Application_ID, $app.Client_Secret, $app.Credential_ID)
    # Saving the AD application data
    $resultJSON = "${workDir}\result_$($userPrincipalName.split('@')[0])_$($app.Application_ID).json"
    $app | ConvertTO-Json | Out-File $resultJSON
    Write-Log -message "The AD application data is saved in the file '${resultJSON}'.`n" -messageType 'INFO' -workDir $workDir
}


Function Register-Cloudaware
{
    <#
        .SYNOPSIS
        New user registration in Cloudaware

        .DESCRIPTION
        Register-Cloudaware is a module to automate the process of a new user registration in Cloudaware CMDB.

        .PARAMETER name
        Name of the AD application to be created. 
        Read more: https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app

        .PARAMETER credentialExpiration
        Expiration date of the AD application credentials, year.

        .PARAMETER certificateFile
        Path to the file containing the certificate.

        .PARAMETER createKeyAndSertificate
        The switch allows to automatically generate .key и .cert and use them in the AD application that is being created.
        The generated files .key и .cert will be available in the directory ~\cloudaware. Files names have the following format: <USER_PRINCIPAL_NAME>_<APP_ID>.

        .PARAMETER redirectUri
        Redirect URI for the AD application to be created
        Read more: 
        https://docs.microsoft.com/en-us/azure/active-directory/develop/reply-url
        https://docs.microsoft.com/en-us/azure/active-directory/develop/quickstart-register-app#add-a-redirect-uri

        .PARAMETER withSubscriptionRole
        The Subscription Id(s) that the newly created AD application will have the role 'Reader' assigned to.
        The value of the parameter withSubscriptionRole to assign the role 'Reader' to the AD application to all Subscription Id(s) that are available to the user: all.
        If the parameter withSubscriptionRole is not specified - the role is ignored.

        .PARAMETER withKeyVaultPolicies
        The Key Vault name(s) where the policy 'list' will be assigned to keys и secrets, so that Key Vault metadata ('Azure Key Vault Key' and 'Azure Key Vault Secret') is accessible by Cloudaware CMDB.
        The value of the parameter withKeyVaultPolicies to grant the AD application with access to Key Vault(s) in the scope of all Subscription Id(s) that are available to the user: all.
        If the parameter withKeyVaultPolicies is not specified - the policy is ignored.

        .PARAMETER withKubernetesRole
        The Subscription Id(s) that the newly created AD application will have the role 'Azure Kubernetes Service Cluster Admin Role' assigned to.
        The value of the parameter withKubernetesRole to assign the role 'Azure Kubernetes Service Cluster Admin Role' to the AD application to all subscriptions that are available to the user: all.
        If the parameter withKubernetesRole is not specified - the role is ignored.

        Read more: https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#azure-kubernetes-service-cluster-admin-role

        .PARAMETER withReservationRole
        The Reservation Order ID(s) that the newly created AD application will have the role 'Reader' assigned to: https://docs.microsoft.com/en-us/azure/cost-management-billing/reservations/prepare-buy-reservation#reservation-scoping-options
        The value of the parameter withReservationRole to assign the role 'Reader' to the AD application to all Subscription Id(s) that are available to the user: all.
        If the parameter withReservationRole is not specified - the role is ignored.

        Read more: https://docs.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#reader
        
        .PARAMETER dryRun
        The switch allows to save the list of parameters and their values that will be used when creating the AD application during the module Register-Cloudaware run. executing the module Register-Cloudaware.
        The saved file will be available in the path ~\cloudaware\dryRunToCreateApp_<USER_PRINCIPAL_NAME>_<APPLICATION_NAME>.json        
        
        .PARAMETER generateTemplate
        The switch allows to automatically generate a .json file that contains a sample structure of required parameters and the guidelines for their population.
        The generated file will be available in path ~\cloudaware\template.json.

        .PARAMETER fromTemplate
        Path to the .json file containing the mentioned parameters.

        .EXAMPLE
        C:\PS> Register-Cloudaware -name cloudaware-api-access -withKeyVaultPolicies keyVaultName_1
            
        .EXAMPLE
        C:\PS> Register-Cloudaware -name cloudaware-api-access `
                                   -withSubscriptionRole 00000000-0000-0000-0000-000000000000 `
                                   -withKeyVaultPolicies @('keyVaultName_1') `
                                   -withReservationRole `
                                   -verbose

        .EXAMPLE
        C:\PS> Register-Cloudaware -fromTemplate '~\cloudaware\register-cloudaware-parameters.json' -verbose

        .EXAMPLE
        C:\PS> Get-Content -Raw '~\cloudaware\register-cloudaware-parameters.json' | ConvertFrom-Json | Register-Cloudaware -verbose

        .NOTES
        FunctionName    : Register-Cloudaware
        Created by      : Cloudaware
        Version         : 1.0.0
        Date Coded      : 01/01/2021
        Modified by     : 
        Date Modified   : 
        More info       : https://docs.cloudaware.com/

        .INPUTS
        Any PSObjects can be piped in Register-Cloudaware.

        .OUTPUTS
        After Register-Cloudaware module run is completed, the parameters required for registration in Cloudaware CMDB will be displayed in the console.
        These parameters will be available in path '~\cloudaware\<USER_PRINCIPAL_NAME>_<APP_ID>_result.json'.
        If switch -createKeyAndSertificate is in place, the files .key and .cert will be generated and available in ~\cloudaware\<USER_PRINCIPAL_NAME>_<APP_ID>.
        Module Register-Cloudaware execution log file is available in '~\cloudaware\log.log'.
        
        .LINK
        Company websites:
        https://www.cloudaware.com/
        https://docs.cloudaware.com/DOCS/Azure-Start-Guide.1171718160.html

        .LINK
        Laern more about Microsoft Resources in Azure Active Directory (not official documentation):
        https://www.shawntabrizi.com/aad/common-microsoft-resources-azure-active-directory/
    #>
    [CmdletBinding()]
    Param 
    (
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        $name = 'cloudaware-api-access',

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateNotNullOrEmpty()]
        $credentialExpiration = 1,

        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        $certificateFile = $null,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$createKeyAndSertificate,

        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        $redirectUri = $null,

        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string[]]$withSubscriptionRole = $null,

        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string[]]$withKeyVaultPolicies = $null,

        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string[]]$withKubernetesRole = $null,

        # https://feedback.azure.com/forums/926206-azure-reservations/suggestions/37614244-create-the-ability-to-give-permissions-to-all-subs
        # https://getnerdio.com/academy/monthly-payments-how-to-save-money-as-csp/
        # https://feedback.azure.com/forums/926206-azure-reservations/suggestions/38261605-managing-permissions-for-azure-reserved-vm-instanc
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string[]]$withReservationRole = $null,

        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$dryRun,

        [Parameter(Mandatory=$false)]
        [switch]$generateTemplate,

        [Parameter(Mandatory=$false)]
        [string]$fromTemplate = $null
    )

    Begin {

        # Creating the working directory if it is not present yet
        $workDir = '~\cloudaware'
        if (-not (Test-Path $workDir)) {
            New-Item -Path $workDir -ItemType 'directory' | Out-Null
        }
        # Checking the switch 'Verbose' to ensure that it is set up
        $verboseEnable = $PSBoundParameters.ContainsKey('Verbose')
        # Sleep duration, seconds
        $sleepDuration = 5
    }

    Process{   

        if ($dryRun) {
            Write-Log -message "The mode to save the list of parameters and their values that will be used for the current module run." -messageType $verboseEnable -workDir $workDir
        }

        if ($generateTemplate) {
            # Generating the template and the module run completion
            Return Get-Template -workDir $workDir
        }

        if ($fromTemplate) {
            # Getting the variables from a json file
            $json = $(Get-ParametersFromFile -fromTemplate $fromTemplate -workDir $workDir)
            # Terminating the module run if the result equals $false
            if ($json -eq $False) {
                Return
            } else {
                $name = $json.name ? $json.name : $name
                $credentialExpiration = $json.credentialExpiration ? $json.credentialExpiration : $credentialExpiration
                $certificateFile = $json.certificateFile
                $redirectUri = $json.redirectUri
                $withSubscriptionRole = $json.withSubscriptionRole
                $withKeyVaultPolicies = $json.withKeyVaultPolicies
                $withKubernetesRole = $json.withKubernetesRole
                $withReservationRole = $json.withReservationRole
            }
        }
   
        # Checking the Azure login and getting Subscription Id(s). Terminating the module run if the result equals $false
        Write-Log -message "Getting Subscription Id(s)." -messageType $verboseEnable -workDir $workDir
        if (($subscriptionId = $(Confirm-AzureCredentials -workDir $workDir)) -eq $False) {Return}
        # The value of 'user principal name' for the current user
        $userPrincipalName = $((Get-AzContext).Account.Id)

        ###################################################################### Starting validation ######################################################################
        Write-Log -message 'Checking the parameters passed by the user.' -messageType 'INFO' -workDir $workDir

        # Checking parameters:
        # $name, $credentialExpiration, $certificateFile, $redirectUri, $withSubscriptionRole, $withKeyVaultPolicies, $withKubernetesRole, $withReservationRole
        # And terminating the module run if the result equals $false
        if (($name = $(Confirm-Properties -parameterValidation $name -workDir $workDir -validatingName)) -eq $False) {Return}
        # Checking the name of AD application to ensure that the name is unique. Terminating the module run if AD application name already exists.
        if ($null -ne (Get-AzADApplication -DisplayName $name).ApplicationId) {
            Write-Log -message "The AD application '${name}' already exists.`n" -messageType 'ERROR' -workDir $workDir
            Return
        }
        if (($credentialExpiration = $(Confirm-Properties -parameterValidation $credentialExpiration -workDir $workDir -validatingCredentialExpiration)) -eq $False) {Return}
        if (($certificateFile = $(Confirm-Properties -parameterValidation $certificateFile -workDir $workDir -validatingCertificateFile)) -eq $False) {Return}
        if (($redirectUri = $(Confirm-Properties -parameterValidation $redirectUri -workDir $workDir -validatingRedirectUri)) -eq $False) {Return}
        if ($subscriptionId) {
            if (($withSubscriptionRole = $(Confirm-Properties -parameterValidation $withSubscriptionRole -subscriptionId $subscriptionId -userPrincipalName $userPrincipalName -workDir $workDir -validatingWithSubscriptionRole)) -eq $False) {Return}
            if ($withKeyVaultPolicies -and ($withKeyVaultPolicies = $(Confirm-Properties -parameterValidation $withKeyVaultPolicies -subscriptionId $subscriptionId -userPrincipalName $userPrincipalName -workDir $workDir -validatingWithKeyVaultPolicies)) -eq $False) {Return}
            if (($withKubernetesRole = $(Confirm-Properties -parameterValidation $withKubernetesRole -subscriptionId $subscriptionId -userPrincipalName $userPrincipalName -workDir $workDir -validatingWithKubernetesRole)) -eq $False) {Return}
            if (($withReservationRole = $(Confirm-Properties -parameterValidation $withReservationRole -subscriptionId $subscriptionId -userPrincipalName $userPrincipalName -workDir $workDir -validatingWithReservationRole)) -eq $False) {Return}

        } elseif (-not $subscriptionId) {
            # If the user has specified values for $withSubscriptionRole, $withKeyVaultPolicies, $withKubernetesRole, $withReservationRole during but the Subscription Id(s) is not available, the module run will be terminated.
            if (($null -ne $withSubscriptionRole) -or ($null -ne $withKeyVaultPolicies) -or ($null -ne $withKubernetesRole) -or ($null -ne $withReservationRole)) {
                Write-Log -message "Impossible to assign role(s) or a policy to the AD application '${name}': Subscription(s) are not available.`n" -messageType 'ERROR' -workDir $workDir
                Return
            }
        }

        if ($dryRun) {
            # Saving the list of parameters that will be used for the current module run, if the condition above is true
            $withReservationRole ? $($withReservationRole = $($withReservationRole | foreach-object {$_.split('/')[-1]})) : $null

            $usedParametersJSON = "${workDir}\dryRunToCreateApp_$($userPrincipalName.split('@')[0])_${name}.json"
            Write-Log -message ("The JSON file containing the parameters and their values to be used for creating AD application '${name}' is saved in: '${rolesAndPolicyJSON}'`n") -messageType 'INFO' -workDir $workDir
            [ordered]@{
                'name' = $name
                'credentialExpiration' = $credentialExpiration
                'certificateFile' = $certificateFile
                'redirectUri' = $redirectUri
                'userPrincipalName' = $userPrincipalName
                'withSubscriptionRole' = $withSubscriptionRole
                'withKeyVaultPolicies' = $withKeyVaultPolicies
                'withKubernetesRole' = $withKubernetesRole
                'withReservationRole' = $withReservationRole
            } | ConvertTO-Json -Depth 4 | Out-File $usedParametersJSON
            Return
        }

        ###################################################################### Starting create and configure the AD application ######################################################################
        Write-Log -message 'Creating and configuring the AD application.' -messageType 'INFO' -workDir $workDir

        Write-Log -message "Registering the AD application '${name}'." -messageType 'INFO' -workDir $workDir
        # Registering the new AD application
        $app = $(Request-Aplication -name $name `
                                    -credentialExpiration $credentialExpiration `
                                    -certificateFile $certificateFile `
                                    -createKeyAndSertificate $createKeyAndSertificate `
                                    -redirectUri $redirectUri `
                                    -userPrincipalName $userPrincipalName `
                                    -sleepDuration $sleepDuration `
                                    -workDir $workDir `
                                    -verboseEnable $verboseEnable)
        # Terminating the module run if the condition below is $False
        if ($app -eq $False) {Return}

        Write-Log -message 'Configuring API permissions: Microsoft Graph, Windows Azure Service Management API and Windows Azure Active Directory.' -messageType 'INFO' -workDir $workDir
        # Microsoft Graph
        # Azure Active Directory Graph
        # Azure Service Management
        # Adding APIs through admin-consent
        $parmiss = $(Add-ApiPermissions -name $app.Name `
                           -appId $app.Application_ID `
                           -userPrincipalName $userPrincipalName `
                           -sleepDuration $sleepDuration `
                           -workDir $workDir `
                           -verboseEnable $verboseEnable)
        # Terminating the module run if the condition below is $False
        if ($parmiss -eq $False) {Return}

        if ($withSubscriptionRole -or $withKeyVaultPolicies -or $withKubernetesRole -or $withReservationRole) {
            Write-Log -message 'Configuring the roles/policies.' -messageType 'INFO' -workDir $workDir
        }

        # Assigning the role 'Reader' to the Subscription Id(s) specified in the variable 'withSubscriptionRole' to discover services created in these Subscription Id(s) in Cloudaware CMDB
        Add-RolesAndPolitics -name $app.Name -appId $app.Application_ID -properties $withSubscriptionRole -workDir $workDir -verboseEnable $verboseEnable -assignToSubscriptionRole
        # Assigning the role 'Azure Kubernetes Service Cluster Admin Role' to the Subscription Id(s) specified in the variable 'withKubernetesRole' to discover Kubernetes services created in these Subscription Id(s) in Cloudaware CMDB
        Add-RolesAndPolitics -name $app.Name -appId $app.Application_ID -properties $withKubernetesRole -workDir $workDir -verboseEnable $verboseEnable -assignToKubernetesRole
        # Assigning the role 'Reader' to Azure Reservation Order id(s) specified in the variable 'withReservationRole' to discover Azure Reservations in Cloudaware
        Add-RolesAndPolitics -name $app.Name -appId $app.Application_ID -properties $withReservationRole -workDir $workDir -verboseEnable $verboseEnable -assignToReservationRole
        # Assigning the policy 'list' to keys and secrets in Key Vault(s) specified in the variable 'withKeyVaultPolicies' to dispay the detailed information on keys and secrets in Cloudaware
        Add-RolesAndPolitics -name $app.Name -appId $app.Application_ID -properties $withKeyVaultPolicies -workDir $workDir -verboseEnable $verboseEnable -subscriptionId $subscriptionId -userPrincipalName $userPrincipalName -assignToKeyVaultPolicy

        Write-Log -message "The AD application parameters for the integration with Cloudaware CMDB were successfully generated." -messageType 'INFO' -workDir $workDir

        # Outputting the AD application parameters and their values required for the integration with Cloudaware CMDB to the console 
        Get-DataIntegration -app $app -userPrincipalName $userPrincipalName -workDir $workDir
    }
    End {}
}
