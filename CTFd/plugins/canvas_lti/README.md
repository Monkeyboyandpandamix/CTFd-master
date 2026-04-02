# Canvas LTI Plugin

This plugin exposes CTFd as a Canvas LTI 1.3 / LTI Advantage tool.

Included pieces:

- OIDC login initiation endpoint
- LTI launch validation against Canvas JWKS
- Tool JWKS endpoint
- Canvas-ready JSON configuration endpoint
- Deep linking response for assignment selection
- Admin configuration page at `/admin/canvas-lti`

Canvas-facing endpoints:

- `/plugins/canvas_lti/login`
- `/plugins/canvas_lti/launch`
- `/plugins/canvas_lti/.well-known/jwks.json`
- `/plugins/canvas_lti/canvas-config.json`
