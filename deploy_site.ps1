[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.IO.Compression.FileSystem

[string[]]$NecessaryFeatures = "Web-Server","Web-Mgmt-Tools","Web-Asp-Net45"
$SiteName = "test.by"
[int]$Port = 80
$ApplicationPoolName = $SiteName
$SiteLocation = $env:systemdrive + "\inetpub\" + $SiteName
$WorkFolder = $env:temp + "\" + $SiteName

$GitOwner = "TargetProcess"
$GitRepo = "DevOpsTaskJunior"
$GitRef = "master"

$TestAccountEmail = "test@gmail.by"
$TestAccountPassword = "123456789^Ab"

$NecessaryFramework = "4.5.2"
[int]$NecessaryFrameworkReleaseVersion = 379893
$NecessaryFrameworkUrl = "https://download.microsoft.com/download/E/2/1/E21644B5-2DF2-47C2-91BD-63C560427900/NDP452-KB2901907-x86-x64-AllOS-ENU.exe"


Function Get-FileFromGit ($FileRepPath) {

    $uri = "https://api.github.com/repos/" + $GitOwner + "/" + $GitRepo + "/contents" + $FileRepPath
    $fileBase64 = (Invoke-RestMethod -Uri $uri).content
    $file = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($fileBase64))
    return $file

}


Function Check-Framework {

    $outFilePath = $WorkFolder + "\" + "Framework.exe"
    $currentFrameworkVersionKey = "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full\"
    $webConfigRepPath = "/Web.config"
    $frameworkWebConfigPattern = "httpRuntime targetFramework=""$($NecessaryFramework)"""
    $frameworkReleaseVersionPattern = "\d\d\d\d\d\d"
    
    $webConfig = Get-FileFromGit $webConfigRepPath

    if ($webConfig -match $frameworkWebConfigPattern)
    {
        if ($NecessaryFrameworkReleaseVersion -match $frameworkReleaseVersionPattern)
        {   
            $installedFrameworkVersion = (Get-ItemProperty -Path $currentFrameworkVersionKey).Release

            if ($installedFrameworkVersion -match $frameworkReleaseVersionPattern)
            {
                if ($installedFrameworkVersion -lt $NecessaryFrameworkReleaseVersion)
                {
                    $message = "Installing framework $($NecessaryFramework)..."
                    Write-Log $message Information

                    Download $NecessaryFrameworkUrl $outFilePath
                    Start-Process -FilePath $outFilePath -ArgumentList "/q /norestart" -Wait -NoNewWindow
                    
                    $message = "Framework $($NecessaryFramework) is installed. Please reboot server for apply changes!"
                    Write-Log $message Warning
                    Send-Report $message
                    break
                }
                else
                {
                    $message = "Framework $($NecessaryFramework) or highter is already installed."
                    Write-Log $message Information
                }
            }
            else
            {
                throw "Installed framework version is invalid!"
            }
        }
        else
        {
            throw "$NecessaryFrameworkReleaseVersion is wrong necessary framework release version!"
        }
    }
    else
    {
        throw "Web.config: <httpRuntime.targetFramework> not equal $($NecessaryFramework)!"
    }  
      
}


Function Check-WindowsFeature {

    foreach ($feature in $NecessaryFeatures) 
    {
        $featureObject = Get-WindowsFeature -Name $feature
      
        if ($featureObject) 
        {
            if ($featureObject.installState -eq "Available")
            {
                Add-WindowsFeature $featureObject.Name
            }
            elseif ($featureObject.installState -ne "Installed")
            {
                throw "$($featureObject.Name) feature has wrong state: $($featureObject.installState)"
            }
        }
        else
        {
            throw "$($feature) feature could not be found!"
        }
    }

}


Function Check-SQL {

    $sqlName = "Microsoft SQL Server 2014 Express LocalDB"
    $url = "https://download.microsoft.com/download/2/A/5/2A5260C3-4143-47D8-9823-E91BB0121F94/ENU/x64/SqlLocalDB.msi"
    $outFilePath = $WorkFolder + "\" + "sql.msi"
    
    $isSQLInstalled = Get-WmiObject Win32_Product | Where {$_.Name -match $sqlName}

    if (!$isSQLInstalled)
    {
        $message = "Installing $($sqlName)..."
        Write-Log $message Information

        Download $url $outFilePath

        $msiArguments = "/i $outFilePath /qn IACCEPTSQLLOCALDBLICENSETERMS=YES"
        Start-Process msiexec -ArgumentList $msiArguments -Wait -NoNewWindow  

        $isSQLInstalled = Get-WmiObject Win32_Product | Where {$_.Name -match $sqlName}

        if (!$isSQLInstalled)
        {
            throw "SQL install is failed!"
        }
    }

}


Function Check-Site ($Action) {

    if (($Action -eq "Register") -or ($Action -eq "Login"))
    {
        $uri = "http://" + $SiteName + ":" + $Port + "/Account/" + $Action
        $passphrase = "Hello $($TestAccountEmail)!"
        $ieescAdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        
        Set-ItemProperty -Path $ieescAdminKey -Name "IsInstalled" -Value 0 -Force
        Rundll32 iesetup.dll, IEHardenAdmin

        $request = Invoke-WebRequest -Uri $uri -SessionVariable session
        $form = $request.Forms[0]
        $form.Fields.Email = $TestAccountEmail
        $form.Fields.Password = $TestAccountPassword      
        if ($Action -eq "Register")
        {
            $form.Fields.ConfirmPassword = $TestAccountPassword
        }
        $request = Invoke-WebRequest -Uri $uri -WebSession $session -Method POST -Body $form.Fields
        
        Set-ItemProperty -Path $ieescAdminKey -Name "IsInstalled" -Value 1 -Force
        
        return $request.Content -match $passphrase
    }
    else
    {
        throw "$($Action) is wrong action!"
    }

}


Function Update-Config {

        $filePath = $SiteLocation + "\" + "Web.config"

        $configBody = Get-Content -Path $filePath
        ($configBody -replace "<system.web.>", "<system.web>").Replace('AttachDbFilename=|DataDirectory|\aspnet-106035748.mdf;', "") | 
            Set-Content -Path $filePath

}


Function Download ($Url, $OutputFilePath) {

    if (!(Test-Path $WorkFolder))
    {
        mkdir $WorkFolder
    }
    else
    {
        rmdir $WorkFolder -Force -Recurse -Verbose
        mkdir $WorkFolder
    }

    Invoke-WebRequest -Uri $Url -OutFile $OutputFilePath

}


Function Check-DNS {

    $dns = "127.0.0.1" + " " + $SiteName
    $hostsPath = "$env:windir" + "\system32\Drivers\etc\hosts"

    if ((Get-Content $hostsPath) -notcontains $dns)
    {
        Add-Content -Encoding UTF8 $hostsPath "`n$dns"
    }

}


Function Check-IIS {

    $sitePath = "IIS:Sites\" + $SiteName
    $applicationPoolPath = "IIS:\AppPools\" + $ApplicationPoolName
    $necessaryIdentityType = "LocalSystem"
    
    if (!(Test-Path $SiteLocation))
    {
        mkdir $SiteLocation
    }

    if (!(Test-Path $applicationPoolPath))
    {
        New-WebAppPool -Name $ApplicationPoolName
    }

    if ((Get-ItemProperty $applicationPoolPath -Name processModel.identityType) -ne $necessaryIdentityType)
    {
        Set-ItemProperty $applicationPoolPath -Name processModel.identityType -Value $necessaryIdentityType
    }

    if (!(Test-Path $sitePath))
    {
        New-WebSite -Name $SiteName -Port $Port -HostHeader $SiteName -PhysicalPath $SiteLocation -ApplicationPool $ApplicationPoolName
    }

}


Function Update-Site {

    $url = "https://github.com/" + $GitOwner + "/" + $GitRepo + "/archive/" + $GitRef + ".zip"
    $outFilePath = $WorkFolder + "\" + "TP.zip"

    if ((Get-WebsiteState $SiteName).value -ne "Stopped")
    {
        Stop-Website $SiteName
    }

    if ((Get-WebAppPoolState $ApplicationPoolName).value -ne "Stopped")
    {
        Stop-WebAppPool $ApplicationPoolName
    }
    
    if (Test-Path $SiteLocation)
    {
        Start-Sleep 5
        rmdir $SiteLocation -Force -Recurse -Verbose
    }

    Download $url $outFilePath
    [System.IO.Compression.ZipFile]::ExtractToDirectory($outFilePath, $WorkFolder)
    Copy-Item -Path (Get-ChildItem -Directory -Path $WorkFolder).FullName -Destination $SiteLocation -Recurse
        
    Update-Config
                
    Start-WebAppPool $ApplicationPoolName
    Start-Website $SiteName

}


Function Send-Report ($Message) {

    $json = "{""text"":""$env:computername $SiteName - $Message""}"
    $uri = "https://hooks.slack.com/services/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"

    Invoke-RestMethod -Method POST -ContentType application/json -Uri $uri -Body $json

    Write-Log $json Information

}


Function Write-Log ($LogMessage, $LogmessageType) {

    Write-Host $LogmessageType - $LogMessage

    $eventID = switch ($LogmessageType)
    {
        Information {1}
        Warning {2}
        Error {3}
    }

    Write-EventLog -LogName Application -Source $SiteName -EntryType $LogmessageType -EventID $eventID -Message $LogMessage

}


Function Main {
    
    $uri = "https://api.github.com/repos/" + $GitOwner + "/" + $GitRepo + "/commits/" + $GitRef
    $latestCommitSHA = (Invoke-RestMethod -Uri $uri).sha
    $envVarName = $SiteName + "_CurrentCommitSHA"
    $currentCommitSHA = [Environment]::GetEnvironmentVariable($envVarName,"Machine")

    if ($latestCommitSHA -eq $currentCommitSHA)
    {
        if (Check-Site Login)
        {
            $message = "Login is succeeded."
            Write-Log $message Information
        }
        else
        {
            throw "Login is failed!"
        }
    }
    elseif ($currentCommitSHA)
    {
        Check-Framework
        Update-Site

        if (Check-Site Login)
        {
            $message = "Update is succeeded."
            Write-Log $message Information
            Send-Report $message
        }
        else
        {
            throw "Update is failed!"
        }
     }
     else
     {   
         Check-WindowsFeature
         Check-Framework
         Check-SQL
         Check-DNS
         Check-IIS
         Update-Site

         if (Check-Site Register)
         {
            $message = "Deployment is succeeded."
            Write-Log $message Information
            Send-Report $message
         }
         else
         {
            throw "Deployment is failed!"
         }
    }

    [Environment]::SetEnvironmentVariable($envVarName, $latestCommitSHA, "Machine")     
}


New-EventLog -LogName Application -Source $SiteName -ErrorAction Ignore

trap
{
    $message = $_.Exception.Message + "`n" + $_.InvocationInfo.PositionMessage
    Write-Log $message Error
    Send-Report "Hmm, it seems like something went wrong! Check logs!"
    break
}

Main
