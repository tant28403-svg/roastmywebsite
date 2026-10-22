# Roast My Website

Open-source website vulnerability and OSINT scanner. Clone it, install it, and scan websites you own or have written permission to test.

```bash
git clone https://github.com/your-org/roast-my-website.git
cd roast-my-website
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
roastmywebsite doctor
```

## Legal and ethical use

Only scan systems you own or have explicit written permission to test. Unauthorized scanning may be illegal. This project is intended for defensive security, authorized penetration testing, and education.

## Quick start

```bash
roastmywebsite recon example.com
roastmywebsite scan example.com --mode safe
roastmywebsite roast example.com --aggressive
roastmywebsite report --format html
```

## Linux setup

```bash
git clone https://github.com/your-org/roast-my-website.git
cd roast-my-website
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
./scripts/install.sh
roastmywebsite doctor
```

## Docker

```bash
docker build -t roastmywebsite .
docker run --rm -it -v "$PWD/reports:/app/reports" roastmywebsite doctor
```

## Documentation

See `docs/` for architecture, modules, safety, and releasing guides.

## License

MIT