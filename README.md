#Démarer le serveur
uvicorn app.main:waf --host 0.0.0.0 --port 8000
#voir tous running servers
netstat -ano | findstr ":8000"
#Tuer TOUS les processus Python/uvicorn d'un coup :
Get-Process python | Stop-Process -Force
#tuer uniquement ceux sur le port 8000:
netstat -ano | findstr "LISTENING.*8000" | ForEach-Object { ($_ -split "\s+")[-1] } | ForEach-Object { taskkill /F /PID $_ }
