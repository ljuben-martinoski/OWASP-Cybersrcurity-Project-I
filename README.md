# OWASP Top 10 Demo Project (Django)

Uses the OWASP Top 10 **2021** list.

## Setup (Windows / Linux / Mac)
1. Install Python 3.11+
2. `pip install django`
3. `python manage.py migrate`
4. `python manage.py runserver`
5. Visit http://127.0.0.1:8000/register/ to create two users, log in as each
   in separate browsers/incognito windows, create a note per user, then try
   the flaws below.

## Flaws (see inline comments in notes/views.py and config/settings.py
   marked "FLAW N" with a commented-out "FIX" directly below each)

1. **Broken Access Control (IDOR)** — `notes/views.py`, `note_detail()`
2. **Injection (SQL Injection)** — `notes/views.py`, `note_search()`
3. **Cryptographic Failures (plaintext passwords)** — `notes/views.py`, `register()` / `login_view()`
4. **Security Misconfiguration** — `config/settings.py` (DEBUG, SECRET_KEY, ALLOWED_HOSTS)
5. **CSRF** — `notes/views.py`, `note_delete()` (`@csrf_exempt`)

Take before/after screenshots per flaw and put them in a `screenshots/` folder
named `flaw-1-before-1.png`, `flaw-1-after-1.png`, etc., per the assignment.
