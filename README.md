# ![](https://github.com/CTFd/CTFd/blob/master/CTFd/themes/core/static/img/logo.png?raw=true)

![CTFd MySQL CI](https://github.com/CTFd/CTFd/workflows/CTFd%20MySQL%20CI/badge.svg?branch=master)
![Linting](https://github.com/CTFd/CTFd/workflows/Linting/badge.svg?branch=master)
[![MajorLeagueCyber Discourse](https://img.shields.io/discourse/status?server=https%3A%2F%2Fcommunity.majorleaguecyber.org%2F)](https://community.majorleaguecyber.org/)
[![Documentation Status](https://api.netlify.com/api/v1/badges/6d10883a-77bb-45c1-a003-22ce1284190e/deploy-status)](https://docs.ctfd.io)

## What is CTFd?

CTFd is a Capture The Flag framework focusing on ease of use and customizability. It comes with everything you need to run a CTF and it's easy to customize with plugins and themes.

![CTFd is a CTF in a can.](https://github.com/CTFd/CTFd/blob/master/CTFd/themes/core/static/img/scoreboard.png?raw=true)

## Local Integrated Lab

This repository is currently set up as a local integrated CTF lab on top of CTFd. In addition to the base CTFd app, it includes imported and Docker-backed challenge content from Juice Shop, WrongSecrets, and curated picoCTF-style examples, plus a Canvas LTI 1.3 / LTI Advantage plugin.

### Current Local Login

- CTFd admin email: `admin@example.com`
- CTFd admin password: `AdminPass123!`

These credentials are for the current local instance. Change them before exposing the platform anywhere outside local testing.

### Current Local Services

- Main CTFd: [http://localhost:8000](http://localhost:8000)
- Nginx front door: [http://localhost](http://localhost)
- Repository review page: [http://localhost:8000/repo-review](http://localhost:8000/repo-review)
- Juice Shop: [http://localhost:3001](http://localhost:3001)
- WrongSecrets: [http://localhost:8081](http://localhost:8081)
- pico Web CSS example: [http://localhost:8083](http://localhost:8083)
- pico artifacts: [http://localhost:8084/start-problem-dev](http://localhost:8084/start-problem-dev)
- pico SSH example: `ssh -p 2222 ctf-player@localhost`
- pico Reversing Python example: `nc localhost 2223`
- pico Perceptron Gate example: `nc localhost 2224`

### Integrated Content

- `juice-shop/juice-shop`
- `juice-shop/juice-shop-ctf`
- `OWASP/wrongsecrets`
- `picoCTF/start-problem-dev`
- reviewed but not force-imported as broken CTFd packs:
  - `apsdehal/awesome-ctf`
  - `pwncollege/ctf-archive`
  - `pwncollege/challenges`

Challenge descriptions in the current seeded catalog include local launch links where appropriate:

- Juice Shop challenges link to `http://localhost:3001`
- WrongSecrets challenges link to `http://localhost:8081`
- picoCTF examples include their local web, SSH, netcat, or artifact endpoints directly in the description

### Running The Stack

Use the project compose files:

```bash
docker compose -f docker-compose.yml -f docker-compose.ctf-content.yml up -d --build
```

To restart just CTFd after plugin or Python changes:

```bash
docker compose -f docker-compose.yml -f docker-compose.ctf-content.yml restart ctfd
```

### Auto Launch

This repo now includes a one-command launcher at [scripts/auto_launch.sh](/Users/mohammadaghamohammadi/Desktop/CTFd-master/scripts/auto_launch.sh).

What it does:

- clones any missing challenge source repositories into `repos/`
- installs and builds `juice-shop-ctf` automatically if needed
- regenerates picoCTF artifacts
- rebuilds the Juice Shop and WrongSecrets CTF exports
- rebuilds the merged integrated challenge CSV
- starts the full Docker stack
- reseeds CTFd with the current integrated content

Run it from the repo root:

```bash
./scripts/auto_launch.sh
```

If the script is not executable yet on your machine:

```bash
chmod +x ./scripts/auto_launch.sh
./scripts/auto_launch.sh
```

After auto-launch completes, use:

- CTFd: [http://localhost:8000](http://localhost:8000)
- Nginx: [http://localhost](http://localhost)
- Juice Shop: [http://localhost:3001](http://localhost:3001)
- WrongSecrets: [http://localhost:8081](http://localhost:8081)
- Canvas admin: [http://localhost:8000/admin/canvas-lti](http://localhost:8000/admin/canvas-lti)

The current local admin login remains:

- Email: `admin@example.com`
- Password: `AdminPass123!`

### Canvas LTI 1.3 / LTI Advantage

This repo includes a Canvas plugin at [CTFd/plugins/canvas_lti/__init__.py](/Users/mohammadaghamohammadi/Desktop/CTFd-master/CTFd/plugins/canvas_lti/__init__.py).

Local plugin endpoints:

- Admin page: [http://localhost:8000/admin/canvas-lti](http://localhost:8000/admin/canvas-lti)
- Status: [http://localhost:8000/plugins/canvas_lti/status](http://localhost:8000/plugins/canvas_lti/status)
- JWKS: [http://localhost:8000/plugins/canvas_lti/.well-known/jwks.json](http://localhost:8000/plugins/canvas_lti/.well-known/jwks.json)
- Canvas config JSON: [http://localhost:8000/plugins/canvas_lti/canvas-config.json](http://localhost:8000/plugins/canvas_lti/canvas-config.json)
- OIDC login endpoint: [http://localhost:8000/plugins/canvas_lti/login](http://localhost:8000/plugins/canvas_lti/login)
- Launch endpoint: [http://localhost:8000/plugins/canvas_lti/launch](http://localhost:8000/plugins/canvas_lti/launch)

Fast setup flow:

1. Open the admin page at `/admin/canvas-lti`.
2. Set `Public Tool Base URL` to a public HTTPS URL that reaches this CTFd instance.
3. In Canvas, create a Developer Key using the plugin's JSON config URL.
4. Install the app in Canvas.
5. Copy the Canvas `Client ID` and `Deployment ID` back into the plugin admin page.
6. Launch once from Canvas to verify user creation and login.

Important constraints:

- Canvas cannot launch a localhost-only tool.
- A public HTTPS URL is required.
- `client_id` and `deployment_id` come from Canvas after app installation.
- The plugin currently covers LTI 1.3 launch flow, tool JWKS, Canvas config generation, and deep linking.
- Full grade passback and roster sync are not implemented yet.

## Features

- Create your own challenges, categories, hints, and flags from the Admin Interface
  - Dynamic Scoring Challenges
  - Unlockable challenge support
  - Challenge plugin architecture to create your own custom challenges
  - Static & Regex based flags
    - Custom flag plugins
  - Unlockable hints
  - File uploads to the server or an Amazon S3-compatible backend
  - Limit challenge attempts & hide challenges
  - Automatic bruteforce protection
- Individual and Team based competitions
  - Have users play on their own or form teams to play together
- Scoreboard with automatic tie resolution
  - Hide Scores from the public
  - Freeze Scores at a specific time
- Scoregraphs comparing the top 10 teams and team progress graphs
- Markdown content management system
- SMTP + Mailgun email support
  - Email confirmation support
  - Forgot password support
- Automatic competition starting and ending
- Team management, hiding, and banning
- Customize everything using the [plugin](https://docs.ctfd.io/docs/plugins/overview) and [theme](https://docs.ctfd.io/docs/themes/overview) interfaces
- Importing and Exporting of CTF data for archival
- And a lot more...

## Install

1. Install dependencies: `pip install -r requirements.txt`
   1. You can also use the `prepare.sh` script to install system dependencies using apt.
2. Modify [CTFd/config.ini](https://github.com/CTFd/CTFd/blob/master/CTFd/config.ini) to your liking.
3. Use `python serve.py` or `flask run` in a terminal to drop into debug mode.

You can use the auto-generated Docker images with the following command:

`docker run -p 8000:8000 -it ctfd/ctfd`

Or you can use Docker Compose with the following command from the source repository:

`docker compose up`

Check out the [CTFd docs](https://docs.ctfd.io/) for [deployment options](https://docs.ctfd.io/docs/deployment/installation) and the [Getting Started](https://docs.ctfd.io/tutorials/getting-started/) guide

## Live Demo

https://demo.ctfd.io/

## Support

To get basic support, you can join the [MajorLeagueCyber Community](https://community.majorleaguecyber.org/): [![MajorLeagueCyber Discourse](https://img.shields.io/discourse/status?server=https%3A%2F%2Fcommunity.majorleaguecyber.org%2F)](https://community.majorleaguecyber.org/)

If you prefer commercial support or have a special project, feel free to [contact us](https://ctfd.io/contact/).

## Managed Hosting

Looking to use CTFd but don't want to deal with managing infrastructure? Check out [the CTFd website](https://ctfd.io/) for managed CTFd deployments.

## MajorLeagueCyber

CTFd is heavily integrated with [MajorLeagueCyber](https://majorleaguecyber.org/). MajorLeagueCyber (MLC) is a CTF stats tracker that provides event scheduling, team tracking, and single sign on for events.

By registering your CTF event with MajorLeagueCyber users can automatically login, track their individual and team scores, submit writeups, and get notifications of important events.

To integrate with MajorLeagueCyber, simply register an account, create an event, and install the client ID and client secret in the relevant portion in `CTFd/config.py` or in the admin panel:

```python
OAUTH_CLIENT_ID = None
OAUTH_CLIENT_SECRET = None
```
