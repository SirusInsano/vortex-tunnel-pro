@echo off
title Vortex Tunnel - Claro/TIM Payload, Split-TLS, IP Hunter & Keep-Alive
cd /d "F:\vortex-tunnel"
echo Iniciando Vortex Tunnel em http://127.0.0.1:9090 ...
start "" "http://127.0.0.1:9090"
node server.js
pause
