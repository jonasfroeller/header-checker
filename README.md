# HTTP Security Header Analyzer

## Overview

This is a Flask-based web application that provides a web interface and REST API to analyze HTTP security headers. It helps developers and security professionals assess the security posture of web applications.  
The system is designed as a simple, lightweight service that performs live HTTP header analysis and presents results through a user-friendly web interface with caching and rate limiting capabilities.

## System Architecture

### Frontend Architecture

- **Technology**: Vanilla JavaScript with Bootstrap for UI components
- **Design Pattern**: Single-page application with dynamic content loading
- **Styling**: Bootstrap dark theme with custom CSS for security grades and smooth animations
- **User Interface**: Clean, responsive design with real-time analysis feedback and shareable results
- **Sharing Feature**: URL-based result sharing with automatic clipboard copy functionality

### Backend Architecture

- **Framework**: Flask (Python) with modular service architecture
- **Design Pattern**: Service-oriented architecture with separation of concerns
- **Core Services**:
  - `HumbleService`: Handles HTTP security header analysis with automatic protocol fallback (HTTPS→HTTP)
  - `CacheService`: Provides in-memory caching with TTL support for performance optimization
  - `URLValidator`: Handles URL validation, normalization, and protocol detection
- **Rate Limiting**: Flask-Limiter integration for API protection (200/day, 50/hour globally, 10/minute per endpoint)
- **Security**: ProxyFix middleware for proper header handling behind proxies

### Data Flow

1. User submits URL through web interface or API (or loads shared URL)
2. URL validation and normalization with automatic protocol detection (HTTPS preferred)
3. Cache check for existing results
4. Security header analysis via custom Python engine if cache miss (with HTTP fallback if HTTPS fails)
5. Result parsing and formatting
6. Response delivery with caching
7. Automatic generation and copying of shareable URL for results

### Error Handling

- Network timeout handling for HTTP requests
- Comprehensive input validation and sanitization
- Rate limiting with meaningful error responses

## External Dependencies

### Core Dependencies

- **Flask**: Web framework for API and web interface
- **Flask-Limiter**: Rate limiting middleware
- **Werkzeug**: WSGI utilities and middleware
- **Bootstrap**: Frontend CSS framework via CDN
- **Font Awesome**: Icon library via CDN

### Security Analysis Engine

- **Custom HTTP Security Header Analyzer**: Built-in Python-based analysis engine that replaces the original humble CLI dependency
- Analyzes 8 key security headers with intelligent scoring and recommendations
- No external CLI dependencies required - uses Python requests library for HTTP analysis

### Runtime Dependencies

- **Python requests library**: For making HTTP requests to analyze security headers
- **Threading**: For thread-safe cache operations
- **JSON**: For parsing analysis results and API responses

### External Services

- **CDN Resources**: Bootstrap CSS and Font Awesome icons loaded from external CDNs
- No database dependencies (uses in-memory caching)
- No external API dependencies

### Environment Configuration

- `SESSION_SECRET`: Flask session secret key (defaults to development key)
- Rate limiting configuration through Flask-Limiter
- Logging configuration set to DEBUG level for development

## Run frontend and backend together

The Flask app serves both the API and the web UI (from `templates/` and `static/`). Start the server with one of the following single commands:

- Using Python (recommended):
  
  ```bash
  python main.py
  ```

- Using Flask CLI (auto-reload):
  
  ```bash
  python -m flask --app app run --debug
  ```

- Using uv (if installed):
  
  ```bash
  uv run python main.py
  ```

Then open http://localhost:5000 in your browser.

## Production Deployment

Use uv to install dependencies, then run the app with a production WSGI server (Gunicorn) behind a reverse proxy.

1) Install dependencies (prod)

```bash
uv sync --frozen --no-dev
```

2) Run with Gunicorn (Linux)

```bash
export SESSION_SECRET="<your-strong-secret>"
gunicorn -w 4 -k gthread -b 0.0.0.0:8000 app:app
```

3) Reverse proxy (Nginx)

```nginx
location / {
  proxy_pass http://127.0.0.1:8000;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
}
```

Notes:
- Gunicorn is not supported on Windows; for local Windows use WSL or a Windows-friendly server (e.g., waitress). For real prod, prefer Linux.
- Set `SESSION_SECRET` in production.

### Install dependencies (first run)

If you don't use `uv`, install the minimal runtime deps with pip:

```bash
python -m pip install --upgrade pip
pip install flask flask-limiter werkzeug requests
```

Optional extras in `pyproject.toml` (e.g., `gunicorn`, `flask-sqlalchemy`) are not yet required to run this app.
