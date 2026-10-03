@echo off
rem Executa o Analisador de Trafego de Rede com um duplo clique (Windows).
rem Equivale a abrir o terminal nesta pasta e rodar: docker compose up --build
cd /d "%~dp0"
title Analisador de Trafego de Rede

echo ============================================================
echo  Analisador de Trafego de Rede
echo ============================================================
echo.

docker --version >nul 2>&1
if errorlevel 1 goto sem_docker

docker info >nul 2>&1
if errorlevel 1 goto docker_parado

rem Remove relatorio de execucoes anteriores, para nao abrir um arquivo antigo
if exist "%~dp0data\relatorio.html" del /q "%~dp0data\relatorio.html"

echo Construindo a imagem...
docker compose build
if errorlevel 1 goto erro
echo.
echo Iniciando a captura de 20 segundos...
echo.
rem 'run' termina sozinho (o 'up' espera uma tecla por causa do menu do Compose)
docker compose run --rm demo

echo.
if exist "%~dp0data\relatorio.html" goto abrir
goto erro

:abrir
echo Concluido. Abrindo o relatorio no navegador...
echo Arquivos gerados na pasta data: relatorio.html e traffic.db
start "" "%~dp0data\relatorio.html"
goto fim

:sem_docker
echo [ERRO] Docker nao encontrado. Instale o Docker Desktop: https://www.docker.com/products/docker-desktop
goto fim

:docker_parado
echo [ERRO] O Docker Desktop nao esta em execucao.
echo Abra o Docker Desktop, espere o motor iniciar e execute este arquivo de novo.
goto fim

:erro
echo [ERRO] O relatorio nao foi gerado. Veja as mensagens acima.

:fim
echo.
pause
