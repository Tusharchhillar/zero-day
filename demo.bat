@echo off
REM ============================================================
REM ZERO-DAY SIH26145 — Demo Script
REM Run from the project root: C:\Users\chhil\OneDrive\Desktop\SIH2026\ZERO-DAY
REM ============================================================

echo.
echo  ==========================================
echo   ZERO-DAY — SIH26145 Demo
echo   Team ZERO DAY | Smart India Hackathon 2026
echo  ==========================================
echo.

REM 1. Show project structure
echo [1/6] Project Structure:
echo ----------------------------------------
dir /s /b src\zero_day\*.py 2>nul | findstr /v __pycache__
echo.
dir /s /b tests\*.py 2>nul | findstr /v __pycache__
echo.

REM 2. Run tests
echo [2/6] Running Tests (26 expected)...
echo ----------------------------------------
python -m pytest tests/ -v --tb=short
echo.

REM 3. Benchmark throughput
echo [3/6] Benchmarking Throughput (5000 events)...
echo ----------------------------------------
python -m zero_day.cli benchmark --events 5000
echo.

REM 4. Replay mixed scenario (instant)
echo [4/6] Replaying Mixed Scenario (rules-only)...
echo ----------------------------------------
python -m zero_day.cli replay data\fixtures\full_scenario.jsonl --speed 0 --limit 100
echo.

REM 5. Replay with NJ-ODE
echo [5/6] Replaying with NJ-ODE Anomaly Detection...
echo ----------------------------------------
python -m zero_day.cli replay data\fixtures\full_scenario.jsonl --speed 0 --model models\njode_v1.pt
echo.

REM 6. Start API server (will block)
echo [6/6] Starting API Server...
echo ----------------------------------------
echo Open http://localhost:8000/docs for Swagger UI
echo Open http://localhost:5173 for Dashboard
echo.
python -m zero_day.cli api --port 8000
