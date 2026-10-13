@echo off
chcp 65001 >nul
cd /d %~dp0
echo ============================================
echo   SEU 素质讲座抢座助手
echo ============================================
where python >nul 2>nul
if errorlevel 1 (
  echo [!] 未检测到 Python,请先安装 Python 3.10+ 并勾选 "Add Python to PATH"
  pause
  exit /b 1
)
python -c "import fastapi, uvicorn, requests, ddddocr" >nul 2>nul
if errorlevel 1 (
  echo [*] 首次运行,正在安装依赖(约1-2分钟,需联网)...
  python -m pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
  if errorlevel 1 (
    echo [!] 依赖安装失败,请检查网络后重试
    pause
    exit /b 1
  )
)
start "" http://127.0.0.1:8787
python -m uvicorn app:app --host 127.0.0.1 --port 8787
pause
