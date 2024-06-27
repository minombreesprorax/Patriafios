@echo off
start ngrok http 25565
.venv\Scripts\python.exe server.py