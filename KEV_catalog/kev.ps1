cd 【作業ディレクトリ】

$date = Get-Date -Format yyyyMMdd
$message = New-Object -ComObject wscript.shell
$path = Join-Path $pwd -ChildPath "KEV"
$path2 = Join-Path $pwd -ChildPath "list"
# KEV フォルダが存在するか確認
if (-Not (Test-Path $path)) {
     Write-Host "$($pwd.Path) へ KEV フォルダを作成します"
     New-Item -ItemType Directory -Path $path | Out-Null
}

# list フォルダが存在するか確認
if (-Not (Test-Path $path2)) {
     Write-Host "$($pwd.Path) へ list フォルダを作成します"
     New-Item -ItemType Directory -Path $path2 | Out-Null
}

# 新しいKEVカタログをダウンロード
Invoke-WebRequest -Uri
"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
-OutFile "$path\now_KEV.json"

# 古いKEVカタログが存在するか確認
if (Test-Path "$path\before_KEV.json") {
     # beforeとafterのファイルサイズを比較
     $before_time = (Get-ItemProperty
"$path\before_KEV.json").LastWriteTime.ToString("yyyy/MM/dd")
     $before_datesize = (Get-ItemProperty "$path\before_KEV.json").Length
     $now_datesize = (Get-ItemProperty "$path\now_KEV.json").Length

     #見づらい気がする。。。
     if ($now_datesize -gt $before_datesize) {
         #nowが大きければ、countの差分をスライスとして使う
         $now_json = ConvertFrom-Json -InputObject (Get-Content
"$path\now_KEV.json" -Raw)
         $before_json = ConvertFrom-Json -InputObject (Get-Content
"$path\before_KEV.json" -Raw)
         $n_count= $now_json.count
         $b_count= $before_json.count
         $slice= $n_count - $b_count
         if ($slice -gt 0 ){
$now_json.vulnerabilities[0..($slice-1)]|ConvertTo-Json |Out-File
.\$date"suumary_KEV_.json"
                              }

     } else {
         $message.Popup("$before_time から更新されていません。", 0, "$date
との比較結果", 0)
     }
} else {
     Write-Host "初回実行または古いファイルが存在しません。"
}
# 現在のファイルを古いファイルとして保存
Rename-Item -Path "$path\before_KEV.json" -NewName
$date"_before_KEV.json" -Force
# now_KEVはbeforeにする。
Write-Host
"now_KEV.jsonをbefore_KEV.jsonにリネームします。今回使用したbeforee_KEV.jsonは
$date`_before_KEV.json として保存されています"
Rename-Item -Path "$path\now_KEV.json" -NewName "before_KEV.json" -Force

#クラス化してaddメソッドを作る。初期化はset。
class sendto {
     [string] $hoge
     [void] Set([string]$INhoge){
         $this.hoge = $INhoge
     }
     [string] Add([string]$Inhoge){
         $this.hoge += $Inhoge
         return $this.$Inhoge
     }
}
$sendto= New-Object sendto

if (Test-Path .\$date"suumary_KEV_.json")
{

#cisa.ps1の出力結果からCVE番号取得
$cvedate = Get-Content .\$date"suumary_KEV_.json" |ConvertFrom-Json

#繰り返し処理。NVDに投げて、レスポンスから値取り出して。。。
foreach($re in ($cvedate.cveID))
{
     $nvd_res= Invoke-RestMethod -uri "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$re"
     $sendto.set($null)
     $sendto.add("CVE: "+ $nvd_res.vulnerabilities.cve.id +"`n")

     #10/24情報追加
     $KEV_dateset = $cvedate | Where-Object { $_.cveID -eq "$re"
}|Select-Object vendorProject, product,knownRansomwareCampaignUse
     $sendto.add("製品ベンダ: "+ $KEV_dateset.vendorProject +"`n")
     $sendto.add("主な製品: "+ $KEV_dateset.product +"`n")
     $sendto.add("ランサムウェアキャンペーンでの使用歴: "+
$KEV_dateset.knownRansomwareCampaignUse +"`n")

     $sendto.add("CVEレコード登録日(JST): "+
(([datetime]$nvd_res.vulnerabilities.cve.published).ToLocalTime()).ToString("yyyy/MM/dd:
HH時") +"`n")

     #3/23　修正
     $latestMetric = $null
     $latestVersion = 0

     # メトリックのバージョンを探索して最新を特定
     foreach ($property in
$nvd_res.vulnerabilities.Cve.metrics.PSObject.Properties)
     {
         if ($property.Name -match "^cvssMetricV(\d+)$")
         {
             $version = [int]$matches[1] # 正規表現でバージョン番号を取得

             # 最大バージョンを更新
             if ($version -gt $latestVersion)
             {
                 $latestVersion = $version
                 $latestMetric = $property.Name
             }
         }
     }
     #CVSS情報を追加する前に、sourceがプライマリのものだけを抽出。なければセカンダリ。
     $nvdMetric =
$nvd_res.vulnerabilities.cve.metrics.$latestMetric|Where-Object {
$_.type -eq "Primary" }
     if ($nvdMetric -eq $null)
     {
         $nvdMetric =
$nvd_res.vulnerabilities.cve.metrics.$latestMetric|Where-Object {
$_.type -eq "Secondary" }
         $SendTo.Add("Secondaryのみ: " + $nvdMetric.source + "`n")
     }
     $SendTo.Add("Primary: " + $nvdMetric.source + "`n")
     $SendTo.Add("CVSSv: " + $nvdMetric.cvssData.version + "`n")
     $SendTo.Add("CVSSベクトル: " + $nvdMetric.cvssData.vectorString + "`n")
     $SendTo.Add("ベーススコア: " + $nvdMetric.cvssData.baseScore + "`n")
     $SendTo.Add("重要度: " + $nvdMetric.cvssData.baseSeverity + "`n")
     $sendto.add("概要: "+ $nvd_res.vulnerabilities.cve.descriptions.value
+ "`n")
     $sendto.add("推奨対応: "+
$nvd_res.vulnerabilities.cve.cisaRequiredAction+"`n")
     $sendto.add("URL: "+
$nvd_res.vulnerabilities.cve.references.url+"`n").Replace(" " ,"`n")

     #txtファイルに出力
     $filename = ($nvd_res.vulnerabilities.cve.id).ToString()
     $sendto.hoge | Out-File -FilePath .\list\"$filename.txt"

     #エンコード。お好きなサービスに送信。
     $hoge= [System.Web.HttpUtility]::UrlEncode($sendto.hoge)
     Invoke-RestMethod -Uri $uri -Method Post -Headers $theHead -Body body=$hoge
}
}else{#前日のKEVと差分が無い場合。エンコード。お好きなサービスに送信。

     $none_message= "none update since $before_time"
     $none_message= [System.Web.HttpUtility]::UrlEncode($none_message)
     Invoke-RestMethod -Uri $uri -Method Post -Headers $theHead -Body body=$none_message
}
