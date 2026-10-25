# 跑步承廷

把 Garmin Connect 的跑步紀錄匯入，就能看到每週跑量、訓練負荷（ACWR）、配速趨勢、心率區間、每月跑量和距離成績推估。

**網址：** https://eastsheep.github.io/Running-Channing/

整個看板只有一個 `index.html` 檔案。手動匯入的檔案只會在你的瀏覽器裡解析，不會上傳。如果開啟自動同步，資料會先加密才存進這個公開 repo，要輸入你設定的資料密碼才看得到。匯入的資料會存在這個瀏覽器，下次打開還在；換了裝置或清除瀏覽資料，就需要重新匯入。

## 自動同步（每天更新，免手動匯出）

repo 裡的 GitHub Actions（`.github/workflows/sync-garmin.yml`）每天台灣時間 06:00 和 22:00 會自動登入 Garmin Connect，抓下全部的跑步紀錄，加密後存成 `data/runs.enc.json`。資料沒有變動時不會提交。

### 第一次設定（用手機的 Safari 就能完成）

1. 打開 https://github.com/Eastsheep/Running-Channing/settings/secrets/actions （畫面太擠的話，點網址列的「ᴀA」，選「要求桌面版網站」）。
2. 按「New repository secret」，依序新增三個 Secret：
   | Name | Secret 要填的內容 |
   |---|---|
   | `GARMIN_EMAIL` | Garmin 登入用的 email |
   | `GARMIN_PASSWORD` | Garmin 密碼 |
   | `DATA_PASSWORD` | 你自己取一組新密碼，用來解鎖看板。不要和 Garmin 密碼相同，建議 12 個字元以上 |
3. 打開 https://github.com/Eastsheep/Running-Channing/actions ，點左側的「同步 Garmin 跑步紀錄」，再按右邊的「Run workflow」→「Run workflow」，手動跑第一次。
4. 大約一分鐘後出現綠色勾勾，就代表成功。打開看板網址，輸入 `DATA_PASSWORD` 就能看到資料。勾選「這台裝置記住密碼」，之後就不用再輸入。

### 注意

- Secret 存進去之後，GitHub 不會再顯示內容，連 repo 擁有者也看不到，只有排程執行時才會用到。
- 加密方式是 AES-256-GCM，金鑰用 PBKDF2-SHA256（25 萬次）從 `DATA_PASSWORD` 推導而來。密碼越長越安全。
- 這是透過非官方的 `garminconnect` 套件登入。如果 Garmin 帳號有開兩步驟驗證，或 Garmin 改版，自動登入可能會失敗，在 Actions 頁面會看到紅色叉叉，這時改用手動匯入即可。
- 要停止自動同步：在 Actions 頁面停用這個 workflow，或刪除那三個 Secret。

## 用手機取得資料（iPhone）

Garmin Connect App 本身沒有匯出功能，要改用 Safari 開網頁版：

1. 用 Safari 開 [connect.garmin.com](https://connect.garmin.com) 並登入。
2. 點網址列左邊的「ᴀA」，選「要求桌面版網站」。網頁要切成電腦版，才會出現匯出按鈕。
3. 進「活動 → 所有活動」，篩選「跑步」。
4. 往下捲到你要的最早日期。注意它只會匯出已經載入在畫面上的資料。
5. 按右上角的「匯出 CSV」，檔案會存到「檔案」App 的「下載項目」。
6. 打開看板網址，按「匯入 Garmin 檔案」，選剛剛的 CSV。

在 iPhone 上直接打開這個 CSV，中文可能會變成亂碼，這是預覽程式的問題，檔案本身沒壞。看板會自動判斷 UTF-8、UTF-16、Big5、GB18030 這幾種編碼，以及逗號或 Tab 分隔的格式。

## 用電腦取得資料

在 connect.garmin.com 進「活動 → 所有活動」，篩選跑步，往下捲到要的日期，再按「匯出 CSV」。中文和英文介面匯出的欄位名稱都認得。

## 取得完整歷史

到 Garmin 帳戶的「資料管理 → 匯出您的資料」送出申請，幾天後會收到下載連結。把 zip 解開（iPhone 在「檔案」App 點一下就會解壓），找到 `DI_CONNECT/DI-Connect-Fitness/` 資料夾裡的 `*_summarizedActivities.json`，直接匯入看板即可。

## 指標說明

- **ACWR（急慢性負荷比）**：近 7 天的負荷，除以近 28 天的週平均負荷。0.8–1.3 是常見的安全區間，高於 1.5 表示加量太快。負荷的計算方式依資料而定：有 TSS 就用 TSS，沒有的話用心率 TRIMP（會用到你設定的最大心率和安靜心率），兩者都沒有就用跑步時間。
- **心率區間**：以最大心率的 50/60/70/80/90% 分成五區，每次跑步依「平均心率」歸到一區。這是近似值，要算到每秒的區間時間需要 FIT 檔。
- **步頻／步幅**：步頻是每分鐘步數；步幅優先用 Garmin 的「平均步幅」，沒有的話用距離 ÷（步頻 × 時間）推算。
- **有氧效率（EF）**：速度（公尺／分鐘）÷ 平均心率，數值上升代表有氧能力進步。
- **配速 × 心率、步頻 × 配速**：散布圖。前者比較近 30 天和更早的紀錄，後者附上步頻和速度的相關係數。跑姿與心率的分析只計入 1.5 km 以上的跑步。
- **距離成績**：在距離達標的跑步中，取平均配速最快的一次，換算成 3K、5K、10K、半馬、全馬的完賽時間。這是推估值，不是 Garmin 的官方紀錄。

## 加入 iPhone 主畫面

用 Safari 打開網址，按下方的分享鍵，選「加入主畫面」。主畫面上會出現「跑步承廷」的圖示，點開後會全螢幕顯示，不會有瀏覽器的網址列。
