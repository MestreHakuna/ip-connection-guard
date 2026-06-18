@echo off
chcp 65001 >nul
setlocal EnableExtensions

title GitHub Publicador - Novo ou Atualizar

set "APP_NAME=GitHub Publicador"
set "MAIN_BRANCH=main"

call :MENU
if /I "%MODO%"=="Cancelar" (
    echo Operacao cancelada.
    pause
    exit /b 0
)

call :CHECK_GIT
call :CONFIRM_FOLDER

if /I "%MODO%"=="Novo" goto NOVO
if /I "%MODO%"=="Atualizar" goto ATUALIZAR

echo [ERRO] Opcao invalida.
pause
exit /b 1


:MENU
set "MENU_RESULT=%TEMP%\github_menu_%RANDOM%_%RANDOM%.txt"
if exist "%MENU_RESULT%" del "%MENU_RESULT%" >nul 2>nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
 "$out='%MENU_RESULT%';" ^
 "$items=@('Novo','Atualizar');" ^
 "$sel=0;" ^
 "while($true){" ^
 "Clear-Host;" ^
 "Write-Host '============================================================' -ForegroundColor Cyan;" ^
 "Write-Host '              GITHUB PUBLICADOR' -ForegroundColor Cyan;" ^
 "Write-Host '============================================================' -ForegroundColor Cyan;" ^
 "Write-Host '';" ^
 "Write-Host 'Use seta para CIMA/BAIXO e ENTER para selecionar.' -ForegroundColor Yellow;" ^
 "Write-Host 'ESC para cancelar.' -ForegroundColor DarkGray;" ^
 "Write-Host '';" ^
 "for($i=0;$i -lt $items.Count;$i++){" ^
 "if($i -eq $sel){Write-Host ('> ' + $items[$i]) -ForegroundColor Green}else{Write-Host ('  ' + $items[$i])}" ^
 "}" ^
 "$k=[Console]::ReadKey($true);" ^
 "if($k.Key -eq 'UpArrow' -and $sel -gt 0){$sel--}" ^
 "elseif($k.Key -eq 'DownArrow' -and $sel -lt ($items.Count-1)){$sel++}" ^
 "elseif($k.Key -eq 'Enter'){Set-Content -Path $out -Value $items[$sel]; exit}" ^
 "elseif($k.Key -eq 'Escape'){Set-Content -Path $out -Value 'Cancelar'; exit}" ^
 "}"

if not exist "%MENU_RESULT%" (
    echo.
    echo [AVISO] Nao consegui abrir o menu com setas.
    echo Escolha manualmente:
    echo [1] Novo
    echo [2] Atualizar
    choice /C 12 /N /M "Escolha [1/2]: "
    if errorlevel 2 (
        set "MODO=Atualizar"
    ) else (
        set "MODO=Novo"
    )
    goto :EOF
)

set /p MODO=<"%MENU_RESULT%"
del "%MENU_RESULT%" >nul 2>nul
goto :EOF


:CHECK_GIT
echo.
echo ============================================================
echo Verificando Git...
echo ============================================================
where git >nul 2>nul
if errorlevel 1 (
    echo [ERRO] Git nao encontrado.
    echo Instale o Git for Windows e execute este arquivo novamente.
    echo.
    pause
    exit /b 1
)
git --version
goto :EOF


:CONFIRM_FOLDER
echo.
echo Pasta atual:
echo %CD%
echo.
choice /C SN /N /M "Esta e a pasta correta do projeto? [S/N]: "
if errorlevel 2 (
    echo.
    echo Operacao cancelada.
    pause
    exit /b 0
)
goto :EOF


:NOVO
cls
echo ============================================================
echo                  MODO NOVO
echo ============================================================
echo Primeiro envio do projeto para um repositorio do GitHub.
echo.

call :SETUP_IDENTITY
call :ENSURE_REPO
call :ENSURE_GITIGNORE
call :LOGIN_OPTIONAL
call :SET_REMOTE_REQUIRED
call :COMMIT_AND_PUSH

goto FIM


:ATUALIZAR
cls
echo ============================================================
echo                  MODO ATUALIZAR
echo ============================================================
echo Atualiza um repositorio que ja existe no GitHub.
echo.

if not exist ".git" (
    echo [AVISO] Esta pasta ainda nao tem repositorio Git inicializado.
    choice /C SN /N /M "Deseja tratar como NOVO e inicializar agora? [S/N]: "
    if errorlevel 2 (
        echo Operacao cancelada.
        pause
        exit /b 0
    ) else (
        goto NOVO
    )
)

choice /C SN /N /M "Deseja alterar/configurar nome e email do Git? [S/N]: "
if not errorlevel 2 (
    call :SETUP_IDENTITY
)

call :ENSURE_GITIGNORE
call :LOGIN_OPTIONAL
call :SET_REMOTE_OPTIONAL
call :PULL_OPTIONAL
call :COMMIT_AND_PUSH

goto FIM


:SETUP_IDENTITY
echo.
echo ============================================================
echo Nome e email do Git
echo ============================================================
echo.

for /f "tokens=*" %%A in ('git config user.name 2^>nul') do set "CURRENT_NAME=%%A"
for /f "tokens=*" %%A in ('git config user.email 2^>nul') do set "CURRENT_EMAIL=%%A"

if not "%CURRENT_NAME%"=="" echo Nome atual neste projeto: %CURRENT_NAME%
if not "%CURRENT_EMAIL%"=="" echo Email atual neste projeto: %CURRENT_EMAIL%
echo.

set /p GIT_NAME=Digite seu nome para o Git: 
set /p GIT_EMAIL=Digite seu email do GitHub: 

if "%GIT_NAME%"=="" (
    echo [ERRO] Nome nao pode ficar vazio.
    pause
    exit /b 1
)

if "%GIT_EMAIL%"=="" (
    echo [ERRO] Email nao pode ficar vazio.
    pause
    exit /b 1
)

echo.
echo Como deseja salvar nome/email?
echo [1] Apenas neste projeto
echo [2] Global, para todos os projetos deste Windows
choice /C 12 /N /M "Escolha [1/2]: "

if errorlevel 2 (
    git config --global user.name "%GIT_NAME%"
    git config --global user.email "%GIT_EMAIL%"
    echo [OK] Nome e email salvos globalmente.
) else (
    git config user.name "%GIT_NAME%"
    git config user.email "%GIT_EMAIL%"
    echo [OK] Nome e email salvos apenas neste projeto.
)

goto :EOF


:ENSURE_REPO
echo.
echo ============================================================
echo Preparando repositorio local
echo ============================================================

if not exist ".git" (
    echo [INFO] Inicializando repositorio Git...
    git init -b %MAIN_BRANCH%
    if errorlevel 1 (
        echo [AVISO] Seu Git pode ser antigo. Tentando modo alternativo...
        git init
        git branch -M %MAIN_BRANCH%
    )
) else (
    echo [OK] Repositorio Git ja existe nesta pasta.
    git branch -M %MAIN_BRANCH% >nul 2>nul
)

goto :EOF


:ENSURE_GITIGNORE
echo.
echo ============================================================
echo Protegendo arquivos locais no .gitignore
echo ============================================================

if not exist ".gitignore" (
    type nul > ".gitignore"
)

findstr /C:"ip_guard_config.json" ".gitignore" >nul 2>nul || echo ip_guard_config.json>>".gitignore"
findstr /C:"ip_guard_errors.log" ".gitignore" >nul 2>nul || echo ip_guard_errors.log>>".gitignore"
findstr /C:"__pycache__/" ".gitignore" >nul 2>nul || echo __pycache__/>>".gitignore"
findstr /C:"*.pyc" ".gitignore" >nul 2>nul || echo *.pyc>>".gitignore"
findstr /C:".venv/" ".gitignore" >nul 2>nul || echo .venv/>>".gitignore"
findstr /C:"venv/" ".gitignore" >nul 2>nul || echo venv/>>".gitignore"
findstr /C:"build/" ".gitignore" >nul 2>nul || echo build/>>".gitignore"
findstr /C:"dist/" ".gitignore" >nul 2>nul || echo dist/>>".gitignore"
findstr /C:"*.spec" ".gitignore" >nul 2>nul || echo *.spec>>".gitignore"

REM Remove do indice sem apagar do PC, caso ja tenha sido adicionado antes.
git rm --cached ip_guard_config.json >nul 2>nul
git rm --cached ip_guard_errors.log >nul 2>nul

echo [OK] .gitignore pronto.
goto :EOF


:LOGIN_OPTIONAL
echo.
echo ============================================================
echo Login no GitHub
echo ============================================================

where gh >nul 2>nul
if not errorlevel 1 (
    echo GitHub CLI encontrado.
    choice /C SN /N /M "Deseja fazer login agora pelo navegador usando GitHub CLI? [S/N]: "
    if errorlevel 2 (
        echo [INFO] Login ignorado. O push pode pedir login depois.
    ) else (
        gh auth login
    )
) else (
    echo [INFO] GitHub CLI nao encontrado.
    echo No push, o Git/Git Credential Manager pode abrir a tela de login.
    echo Nao coloque senha ou token dentro deste BAT.
)

goto :EOF


:SET_REMOTE_REQUIRED
echo.
echo ============================================================
echo Repositorio remoto
echo ============================================================
echo Cole a URL HTTPS do repositorio do GitHub.
echo Exemplo:
echo https://github.com/seuusuario/nome-do-repositorio.git
echo.

set /p REPO_URL=URL do repositorio: 

if "%REPO_URL%"=="" (
    echo [ERRO] Para NOVO envio, a URL do repositorio e obrigatoria.
    pause
    exit /b 1
)

git remote get-url origin >nul 2>nul
if errorlevel 1 (
    git remote add origin "%REPO_URL%"
) else (
    git remote set-url origin "%REPO_URL%"
)

echo.
echo Remote configurado:
git remote -v

goto :EOF


:SET_REMOTE_OPTIONAL
echo.
echo ============================================================
echo Repositorio remoto
echo ============================================================

git remote get-url origin >nul 2>nul
if not errorlevel 1 (
    for /f "tokens=*" %%A in ('git remote get-url origin') do set "CURRENT_REMOTE=%%A"
    echo Remote atual:
    echo %CURRENT_REMOTE%
    echo.
)

echo Cole a URL HTTPS do repositorio do GitHub.
echo Em ATUALIZAR, pode deixar vazio para usar o remote atual.
echo Exemplo:
echo https://github.com/seuusuario/nome-do-repositorio.git
echo.

set /p REPO_URL=URL do repositorio: 

if "%REPO_URL%"=="" (
    git remote get-url origin >nul 2>nul
    if errorlevel 1 (
        echo [ERRO] Nenhuma URL informada e nenhum remote origin configurado.
        pause
        exit /b 1
    )
) else (
    git remote get-url origin >nul 2>nul
    if errorlevel 1 (
        git remote add origin "%REPO_URL%"
    ) else (
        git remote set-url origin "%REPO_URL%"
    )
)

echo.
echo Remote configurado:
git remote -v

goto :EOF


:PULL_OPTIONAL
echo.
echo ============================================================
echo Sincronizar antes de enviar
echo ============================================================
choice /C SN /N /M "Deseja executar git pull --rebase antes de enviar? [S/N]: "
if errorlevel 2 (
    echo [INFO] Pull ignorado.
    goto :EOF
)

echo.
echo [INFO] Sincronizando com origin/%MAIN_BRANCH%...
git pull --rebase origin %MAIN_BRANCH%
if errorlevel 1 (
    echo.
    echo [ERRO] Falha no pull --rebase.
    echo Pode haver conflito ou o repositorio remoto pode estar vazio.
    echo Resolva o conflito manualmente ou tente atualizar sem pull.
    pause
    exit /b 1
)

goto :EOF


:COMMIT_AND_PUSH
echo.
echo ============================================================
echo Commit e envio
echo ============================================================

set /p COMMIT_MSG=Mensagem do commit [Atualizacao]: 
if "%COMMIT_MSG%"=="" set "COMMIT_MSG=Atualizacao"

echo.
echo [INFO] Adicionando arquivos...
git add .

REM Garante que config/log nao vao subir, mesmo se usuario adicionou antes.
git rm --cached ip_guard_config.json >nul 2>nul
git rm --cached ip_guard_errors.log >nul 2>nul

echo.
echo [INFO] Verificando alteracoes para commit...
git diff --cached --quiet
if not errorlevel 1 (
    echo [INFO] Nao ha novas alteracoes para commit.
) else (
    echo [INFO] Criando commit...
    git commit -m "%COMMIT_MSG%"
    if errorlevel 1 (
        echo [ERRO] Falha ao criar commit.
        pause
        exit /b 1
    )
)

echo.
echo [INFO] Enviando para o GitHub...
git push -u origin %MAIN_BRANCH%
if errorlevel 1 (
    echo.
    echo [ERRO] Falha no push.
    echo Possiveis causas:
    echo - URL do repositorio errada
    echo - Voce ainda nao fez login no GitHub
    echo - O repositorio remoto tem arquivos que voce ainda nao baixou
    echo - Branch remota diferente de %MAIN_BRANCH%
    echo.
    pause
    exit /b 1
)

goto :EOF


:FIM
echo.
echo ============================================================
echo [OK] Operacao finalizada com sucesso!
echo Modo usado: %MODO%
echo ============================================================
echo.
pause
endlocal
exit /b 0
