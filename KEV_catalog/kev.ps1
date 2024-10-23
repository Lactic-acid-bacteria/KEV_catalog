$date = Get-Date -Format yyyyMMdd
$message = New-Object -ComObject wscript.shell
$path = Join-Path $pwd -ChildPath "KEV"

# KEV フォルダが存在するか確認
if (-Not (Test-Path $path)) {
    Write-Host "$($pwd.Path) へ KEV フォルダを作成します"
    New-Item -ItemType Directory -Path $path | Out-Null
}

# 新しいKEVカタログをダウンロード
Invoke-WebRequest -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -OutFile "$path\now_KEV.json"

# 古いKEVカタログが存在するか確認
if (Test-Path "$path\before_KEV.json") {
    # beforeとafterのファイルサイズを比較
    $before_time = (Get-ItemProperty "$path\before_KEV.json").CreationTime.ToString("yyyy/MM/dd")
    $before_datesize = (Get-ItemProperty "$path\before_KEV.json").Length
    $now_datesize = (Get-ItemProperty "$path\now_KEV.json").Length

    #nowが大きければ、countの差分をスライスとして使う
    if ($now_datesize -gt $before_datesize) {
        $now_json = ConvertFrom-Json -InputObject (Get-Content "$path\now_KEV.json" -Raw)
        $before_json = ConvertFrom-Json -InputObject (Get-Content "$path\before_KEV.json" -Raw)
        $n_count= $now_json.count
        $b_count= $before_json.count
        $slice= $n_count - $b_count
        if ($slice -gt 0 ){
            $now_json.vulnerabilities[0..($slice-1)]|ConvertTo-Json |Out-File .\$date"suumary_KEV_.json"
                             }

    } else {
        $message.Popup("$before_time から更新されていません。", 0, "$date との比較結果", 0)
    }
} else {
    Write-Host "初回実行または古いファイルが存在しません。"
}
# 現在のファイルを古いファイルとして保存
Rename-Item -Path "$path\before_KEV.json" -NewName $date"_before_KEV.json" -Force
# now_KEVはbeforeにする。
Write-Host "now_KEV.jsonをbefore_KEV.jsonにリネームします。今回使用したbeforee_KEV.jsonは $date`_before_KEV.json として保存されています"
Rename-Item -Path "$path\now_KEV.json" -NewName "before_KEV.json" -Force
