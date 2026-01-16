
## Quickstart
1. Create a Python virtualenv (recommended).
2. `pip install -r requirements.txt`
3. Run `python app.py` as Administrator (Windows).
4. Open `http://127.0.0.1:5000` to view the dashboard.

Files:
- `app.py` — Flask backend and control endpoints
- `detector.py` — detection rules and state
- `packet_sniffer.py` — pydivert integration
- `firewall.py` — drop logic
- `templates/index.html` — simple UI
- `static/main.js` — dashboard .JS


