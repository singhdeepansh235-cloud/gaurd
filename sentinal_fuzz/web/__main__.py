"""Entry point: python -m sentinal_fuzz.web"""

import uvicorn
import argparse

try:
    from dotenv import load_dotenv
    load_dotenv()  # loads .env from project root
except ImportError:
    pass  # python-dotenv not installed; rely on system env vars


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinal-Fuzz Web Interface")
    parser.add_argument("--host", default="::", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    import os
    port = int(os.environ.get("PORT", args.port))

    print()
    print("=" * 60)
    print("  [*] Sentinal-Fuzz Web Interface")
    print("=" * 60)
    print(f"  Open in browser: http://{args.host}:{port}")
    print("=" * 60)
    print()

    uvicorn.run(
        "sentinal_fuzz.web.app:create_app",
        factory=True,
        host=args.host,
        port=port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
