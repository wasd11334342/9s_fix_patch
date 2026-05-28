使用說明：
1.須將cpp檔編譯成DLL，第一頁的cpp是初版，用來測試DLL有沒有載入成功，用dll_test裡面的cpp，編譯指令為：cmake --build build --config Release
2.需使用其他工具例如CFF Eplorer把online.exe的DLL匯入表修改，先備份online.exe，開啟CFF Eplorer後新增步驟一編譯完成的DLL會產生新的online.exe，最後把DLL跟修改過的exe放進9splay資料夾
3.正常開啟輔助即可生效，開啟帳號登入介面時會自動讀取DLL，目前功能設定為載入後右下角出現一個視窗顯示PID和目前有修復的功能，提示窗會再三秒後自動關閉

版本紀錄：
2026/5/28 初版，修復龍脈尋寶
2026/5/25 更版，修復砸蛋，但是不確定是從哪裡開始，輔助的視窗拖曳時變得異常的卡，
