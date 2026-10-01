# Context-Aware Android SAST

Static analysis for Android APKs that combines manifest exposure, bounded data-flow tracking, validation checks, and detector-specific rules.

## Features

- Detects intent redirection, unsafe WebViews, exposed providers, deep-link abuse, and attacker-controlled class loading.
- Produces terminal summaries, JSON reports, and source-to-sink evidence.
- Includes a local web dashboard for APK upload and review.

## Setup

Requires Python 3.11 or later.

```bash
python -m pip install -e .
```

## Usage

```bash
python cli.py --apk path\to\app.apk
python cli.py --apk path\to\app.apk --output results.json --show-near-code
```

Start the dashboard:

```bash
python dashboard_server.py
```

Open `http://127.0.0.1:8000/dashboard/`.
