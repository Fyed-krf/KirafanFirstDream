$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrEmpty($env:KRF_FD_API_KEY)) {
    throw "env:KRF_FD_API_KEY is empty"
}
if ([string]::IsNullOrEmpty($env:KRF_FD_API_SECRET)) {
    throw "env:KRF_FD_API_SECRET is empty"
}

function Wait-ApiCall {
    [CmdletBinding()]
    param ()

    Start-Sleep -Seconds 5
}

function Get-ResponseParameter {
    [CmdletBinding()]
    param (
        [string]$resp
    )

    $respObj = [PSCustomObject]@{}

    if ([string]::IsNullOrEmpty($resp)) {
        $respObj
        return
    }

    @($resp -split '&') | ForEach-Object {
        $nameVal = @($_ -split '=')
        if ($nameVal.Length -eq 1) {
            $name = [uri]::UnescapeDataString($nameVal)
            Add-Member -InputObject $respObj -MemberType NoteProperty -Name $name -Value $null
        }
        elseif ($nameVal.Length -ge 2) {
            $name = [uri]::UnescapeDataString($nameVal[0])
            $val = [uri]::UnescapeDataString($nameVal[1])
            Add-Member -InputObject $respObj -MemberType NoteProperty -Name $name -Value $val
        }
    }
    $respObj
}

function Invoke-Dispose {
    [CmdletBinding()]
    param (
        [System.IDisposable]$Object
    )

    if ($null -ne $Object) {
        try {
            $Object.Dispose()
        }
        catch {
            $_ | Out-String | Write-Warning
            Write-Warning '----------------------------------------'
            $_.ScriptStackTrace | Out-String | Write-Warning
        }
    }
}

function Get-AuthorizationHeaderValue {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('GET', 'POST')]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$BaseUri,

        [System.Collections.IDictionary]$OAuthUserParams = @{},

        [System.Collections.IDictionary]$UriParams = @{},

        [System.Collections.IDictionary]$BodyParams = @{},

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ConsumerSecuret,

        [string]$TokenSecret = ""
    )

    $signatureSeeds = @{}
    $oauthParams = @{}

    $OAuthUserParams.Keys | ForEach-Object {
        $key = $_
        $signatureSeeds[$key] = $OAuthUserParams[$key]
        $oauthParams[$key] = $OAuthUserParams[$key]
    }
    $UriParams.Keys | ForEach-Object {
        $key = $_
        $signatureSeeds[$key] = $UriParams[$key]
    }
    $BodyParams.Keys | ForEach-Object {
        $key = $_
        $signatureSeeds[$key] = $BodyParams[$key]
    }


    $signatureSeeds['oauth_signature_method'] = 'HMAC-SHA1'
    $signatureSeeds['oauth_timestamp'] = [int]([System.DateTimeOffset]::Now - [System.DateTimeOffset]'1970-01-01T00:00:00Z').TotalSeconds
    $signatureSeeds['oauth_nonce'] = (New-Guid).Guid
    $signatureSeeds['oauth_version'] = '1.0'

    $parameterString = (@($signatureSeeds.Keys | Sort-Object | ForEach-Object {
        $rawKey = $_
        $rawVal = $signatureSeeds[$rawKey]
        $encodedKey = [uri]::EscapeDataString($rawKey)
        $encodedVal = [uri]::EscapeDataString($rawVal)
        "${encodedKey}=${encodedVal}"
    }) -join '&')

    $signatureBaseString = "$($Method.ToUpper())&$([uri]::EscapeDataString($BaseUri))&$([uri]::EscapeDataString($parameterString))"

    $signingKey = "$([uri]::EscapeDataString($ConsumerSecuret))&$([uri]::EscapeDataString($TokenSecret))"

    $utf8 = [System.Text.UTF8Encoding]::new()
    $signingKeyBytes = $utf8.GetBytes($signingKey)
    $signatureBaseStringBytes = $utf8.GetBytes($signatureBaseString)
    $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($signingKeyBytes)
    try {
        $hashBytes = $hmacsha1.ComputeHash($signatureBaseStringBytes)
        $signature = [System.Convert]::ToBase64String($hashBytes)
    }
    finally {
        Invoke-Dispose -Object $hmacsha1
    }

    $oauthParams['oauth_signature_method'] = $signatureSeeds['oauth_signature_method']
    $oauthParams['oauth_signature'] = $signature
    $oauthParams['oauth_timestamp'] = $signatureSeeds['oauth_timestamp']
    $oauthParams['oauth_nonce'] = $signatureSeeds['oauth_nonce']
    $oauthParams['oauth_version'] = $signatureSeeds['oauth_version']

    $oauthParamString = (@($oauthParams.Keys | ForEach-Object {
        $rawKey = $_
        $rawVal = $oauthParams[$rawKey]
        $encodedKey = [uri]::EscapeDataString($rawKey)
        $encodedVal = [uri]::EscapeDataString($rawVal)
        "${encodedKey}=`"${encodedVal}`""
    }) -join ', ')

    "OAuth ${oauthParamString}"
}

function Test-AccountLocked {
    [CmdletBinding()]
    param (
        [System.Management.Automation.ErrorRecord]$ErrorObject,

        [string]$ErrorCodeToCheck = 326
    )

    $errorMessage = ($ErrorObject)?.ToString()
    if ([string]::IsNullOrEmpty($errorMessage)) {
        $false
        return
    }

    try {
        $msgObj = ConvertFrom-Json -InputObject $errorMessage
        $errorCode = ($msgObj)?.errors?[0]?.code
        if ($errorCode -eq $ErrorCodeToCheck) {
            $true
        }
        else {
            $false
        }
    }
    catch {
        $err = $_
        $err | Out-String | Write-Warning
        Write-Warning '----------------------------------------'
        $err.ScriptStackTrace | Out-String | Write-Warning

        $false
        return
    }
}

if (([string]::IsNullOrEmpty($env:KRF_FD_ACCESS_TOKEN)) -or ([string]::IsNullOrEmpty($env:KRF_FD_ACCESS_TOKEN_SECRET))) {
    $oauthUserParams = @{
        oauth_consumer_key = $env:KRF_FD_API_KEY
        oauth_callback = 'oob'
    }
    
    $endpointUri = 'https://api.twitter.com/oauth/request_token'
    $authorizationHeaderValue = Get-AuthorizationHeaderValue -Method 'POST' -BaseUri $endpointUri -OAuthUserParams $oauthUserParams -ConsumerSecuret $env:KRF_FD_API_SECRET
    $headers = @{
        Authorization = $authorizationHeaderValue
    }
    Wait-ApiCall
    $resp = Invoke-RestMethod -Method Post -Uri $endpointUri -Headers $headers -SessionVariable 'session' -Verbose -StatusCodeVariable 'statusCode'
    if (([int]$statusCode) -ne 200) {
        throw "status code does not indicate success: ${statusCode}"
    }
    if ($resp -isnot [string]) {
        $resp | Out-String | Write-Host
        throw 'output of /oauth/request_token is not a string'
    }
    $requestTokenResponse = Get-ResponseParameter -resp $resp
    if ($requestTokenResponse.oauth_callback_confirmed -ne 'true') {
        $requestTokenResponse | Format-List | Out-String | Write-Host
        throw 'oauth_callback_confirmed is not true'
    }
    if ([string]::IsNullOrEmpty($requestTokenResponse.oauth_token)) {
        $requestTokenResponse | Format-List | Out-String | Write-Host
        throw 'oauth_token is null or empty'
    }
    if ([string]::IsNullOrEmpty($requestTokenResponse.oauth_token_secret)) {
        $requestTokenResponse | Format-List | Out-String | Write-Host
        throw 'oauth_token_secret is null or empty'
    }
    
    $redirectUri = "https://api.twitter.com/oauth/authorize?oauth_token=$([uri]::EscapeDataString($requestTokenResponse.oauth_token))"
    Start-Process -FilePath $redirectUri
    $oauthVerifier = Read-Host -Prompt 'enter pin code'
    
    
    
    $oauthUserParams = @{
        oauth_consumer_key = $env:KRF_FD_API_KEY
        oauth_token = $requestTokenResponse.oauth_token
        oauth_verifier = $oauthVerifier
    }
    $endpointUri = 'https://api.twitter.com/oauth/access_token'
    $authorizationHeaderValue = Get-AuthorizationHeaderValue -Method 'POST' -BaseUri $endpointUri -OAuthUserParams $oauthUserParams -ConsumerSecuret $env:KRF_FD_API_SECRET
    $headers = @{
        Authorization = $authorizationHeaderValue
    }
    Wait-ApiCall
    $resp = Invoke-RestMethod -Method Post -Uri $endpointUri -Headers $headers -WebSession $session -Verbose -StatusCodeVariable 'statusCode'
    if (([int]$statusCode) -ne 200) {
        throw "status code does not indicate success: ${statusCode}"
    }
    $accessTokenResponse = Get-ResponseParameter -resp $resp
    $accessTokenResponse = Get-ResponseParameter -resp $resp
    if ([string]::IsNullOrEmpty($accessTokenResponse.oauth_token)) {
        $accessTokenResponse | Format-List | Out-String | Write-Host
        throw 'oauth_token is null or empty'
    }
    if ([string]::IsNullOrEmpty($accessTokenResponse.oauth_token_secret)) {
        $accessTokenResponse | Format-List | Out-String | Write-Host
        throw 'oauth_token_secret is null or empty'
    }
    if ([string]::IsNullOrEmpty($accessTokenResponse.user_id)) {
        $accessTokenResponse | Format-List | Out-String | Write-Host
        throw 'user_id is null or empty'
    }
    if ([string]::IsNullOrEmpty($accessTokenResponse.screen_name)) {
        $accessTokenResponse | Format-List | Out-String | Write-Host
        throw 'screen_name is null or empty'
    }

    $accessTokenResponse | Format-List | Out-String | Write-Host

    $env:KRF_FD_ACCESS_TOKEN = $accessTokenResponse.oauth_token
    $env:KRF_FD_ACCESS_TOKEN_SECRET = $accessTokenResponse.oauth_token_secret
}

$oauthUserParams = @{
    oauth_consumer_key = $env:KRF_FD_API_KEY
    oauth_token = $env:KRF_FD_ACCESS_TOKEN
}

$todayFileName = "like_list_$((Get-Date).ToString('yyyyMMdd'))"
$todayFile = Join-Path -Path $PSScriptRoot -ChildPath $todayFileName
if (-not (Test-Path -LiteralPath $todayFile)) {
    New-Item -Path $todayFile -ItemType File > $null
}
$todayLikes = @(Get-Content -LiteralPath $todayFile -Encoding utf8 | Where-Object {
    $_ -match '^\d+'
})

$targetLikeCount = 120
$todayLikesCount = $todayLikes.Count

$minId = -1

while ($todayLikesCount -lt $targetLikeCount) {
    $bodyParams = @{
        q = '#きらファン初夢'
        result_type = 'recent'
        count = 100
    }
    Write-Host "min id check: ${minId}"
    if ($minId -gt 0) {
        $bodyParams.Add('max_id', $minId-1)
    }
    $endpointUri = 'https://api.twitter.com/1.1/search/tweets.json'
    $authorizationHeaderValue = Get-AuthorizationHeaderValue -Method 'GET' -BaseUri $endpointUri -OAuthUserParams $oauthUserParams -ConsumerSecuret $env:KRF_FD_API_SECRET -BodyParams $bodyParams -TokenSecret $env:KRF_FD_ACCESS_TOKEN_SECRET
    $headers = @{
        Authorization = $authorizationHeaderValue
    }
    Wait-ApiCall
    $resp = Invoke-RestMethod -Method Get -Uri $endpointUri -Headers $headers -WebSession $session -Verbose -StatusCodeVariable 'statusCode' -Body $bodyParams
    if (([int]$statusCode) -ne 200) {
        throw "status code does not indicate success: ${statusCode}"
    }
    if ($resp.statuses.Length -eq 0) {
        throw 'last page'
    }
    $tweets = @($resp.statuses | Where-Object text -CNotMatch '^RT ' | ForEach-Object {
        [PSCustomObject]@{
            id = [long]$_.id
            text = $_.text -replace '[\r\n]+', ' '
            user="$($_.user.name)@$($_.user.screen_name)"
        }
    })
    $tweets | ForEach-Object {
        try {
            $tweet = $_

            $matchedId = $todayLikes | ForEach-Object {
                [long](($_ -split '\|')[0])
            } | Where-Object {
                $tweet.id -eq $_
            } | Select-Object -First 1

            if ($null -ne $matchedId) {
                Write-Host "skip ${matchedId}"
            }
    
            if ($null -eq $matchedId) {
                $bodyParams = @{
                    id = $tweet.id
                }
                $endpointUri = 'https://api.twitter.com/1.1/favorites/create.json'
                $authorizationHeaderValue = Get-AuthorizationHeaderValue -Method 'POST' -BaseUri $endpointUri -OAuthUserParams $oauthUserParams -ConsumerSecuret $env:KRF_FD_API_SECRET -BodyParams $bodyParams -TokenSecret $env:KRF_FD_ACCESS_TOKEN_SECRET
                $headers = @{
                    Authorization = $authorizationHeaderValue
                }
                Wait-ApiCall
                Invoke-RestMethod -Method Post -Uri $endpointUri -Headers $headers -WebSession $session -Verbose -StatusCodeVariable 'statusCode' -Body $bodyParams > $null
                if (([int]$statusCode) -ne 200) {
                    throw "status code does not indicate success: ${statusCode}"
                }
        
                $todayLikes = @(Get-Content -LiteralPath $todayFile -Encoding utf8 | Where-Object {
                    $_ -match '^\d+'
                })
                $likedTweet = "$($tweet.id)|$($tweet.user)|$($tweet.text)"
                $todayLikes += $likedTweet
                $todayLikes | Out-File -LiteralPath $todayFile -Encoding utf8 -Width ([int]::MaxValue)
                $todayLikesCount = $todayLikes.Length
                Write-Host "(${todayLikesCount}/${targetLikeCount}) ${likedTweet}"
            }
                
        }
        catch {
            $err = $_
            $locked = Test-AccountLocked -ErrorObject $err
            if ($locked) {
                throw $err
            }
            else {
                $err | Out-String | Write-Warning
                Write-Warning '----------------------------------------'
                $err.ScriptStackTrace | Out-String | Write-Warning
            }

        }
    }

    $minId = [long]($resp.statuses | ForEach-Object { [long]$_.id } | Measure-Object -Minimum | Select-Object -ExpandProperty Minimum)
    Write-Host "min id get: ${minId}"
}
