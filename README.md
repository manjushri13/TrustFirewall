# TrustFirewall

TrustFirewall is a web app for monitoring security around connected AI agents. It includes a FastAPI backend and a React frontend.

## Requirements

- Python installed and available as `python` in Command Prompt
- Node.js and npm installed and available on `PATH`
- Internet access the first time you install dependencies

## Start the application on Windows

Keep `start-trustfirewall.bat` and `start-trustfirewall.ps1` together in this project folder. From Command Prompt, run:

```bat
start-trustfirewall.bat
```

The launcher checks and installs the backend and frontend dependencies, then starts the backend and frontend in separate windows. It uses the existing backend virtual environment at `backend\.venv` or creates it if needed.

When both services are ready, open:

<http://localhost:5173>

The backend health endpoint is <http://127.0.0.1:8001/health>. The frontend proxies API requests to the backend on port `8001`. The launcher reuses services already responding on the expected ports and reports an error if a port is occupied by a service that is not responding correctly.

To stop the services, close the terminal windows opened for the backend and frontend.

## Configure Gemini security analysis

The backend reads `GEMINI_API_KEY` from `backend\.env` for its Gemini-powered
security analysis. If `backend\.env` does not exist, copy the example file.
Then open `backend\.env` and set the key:

```powershell
if (-not (Test-Path backend\.env)) { Copy-Item backend\.env.example backend\.env }
notepad backend\.env
```

Add or replace this line with the key you obtained from Google AI Studio:

```text
GEMINI_API_KEY=your_real_gemini_api_key
```

Restart the backend after saving.
Keep the key in the backend `.env` file only; do not put it in frontend files
or commit it to Git. The `.env` file is ignored by Git. This enables Gemini
security analysis; it does not configure Gemini as a connected AI agent.

## Run the services manually

In one terminal, start the backend:

```bat
cd backend
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8001
```

In a second terminal, start the frontend:

```bat
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

## Troubleshooting

- If `python` or `npm` is not recognized, install Python or Node.js and reopen Command Prompt so the updated `PATH` is loaded.
- If dependency installation fails, check your internet connection and review the error in the launcher window.
- If the launcher reports that port `8001` or `5173` is occupied, stop the other application using that port and run the launcher again.
- Keep the backend and frontend terminal windows open while using the app.
