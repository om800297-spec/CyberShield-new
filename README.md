
# Cyber Shield Advanced Major Project

A single Flask project structured like the user's existing:
- `app.py`
- `model.py`
- `static/`
- `templates/`
- `requirements.txt`

## Included features

- Professional cybersecurity dashboard
- URL/phishing checker
- Email checker
- Mobile number checker
- Suspicious message analyzer
- Bank scam checker
- IP checker
- Incident management
- Incident report generation workflow
- PDF incident report generation and download
- Evidence/notes field for reporting packages
- Evidence/reporting preparation
- Report-to-authorities workflow
- Sender location/network metadata module
- Cyber awareness center
- Dark/light mode
- Responsive UI
- Health/API status
- Server-side scanning endpoints

## Run in VS Code / Windows

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

http://127.0.0.1:5000

## Deployment

This Flask app can be deployed as one web service on Render, Railway, PythonAnywhere, or another Flask-compatible host.

For Render:
- Build command: `pip install -r requirements.txt`
- Start command: `gunicorn app:app`

For production, add:
- `gunicorn`
- a persistent database
- server-side API keys through environment variables
- rate limiting
- HTTPS/security headers
- real authorized threat-intelligence providers
- PDF generation
- official reporting links for the target jurisdiction

## Location tracking safety

The Sender Metadata module is deliberately **not a covert live-person tracker**. It should only process lawful, authorized IP/network metadata and must not be used to secretly locate a person.

## Police/cybercrime reporting

The project prepares an incident/reporting package for the user. It does not falsely claim that a police complaint was filed. A production version should link the user to the appropriate official government reporting channel and only automate submission if an official API/process explicitly permits it.
