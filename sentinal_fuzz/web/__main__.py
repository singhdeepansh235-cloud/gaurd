"""Entry point: python -m sentinal_fuzz.web"""

import uvicorn
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinal-Fuzz Web Interface")
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    args = parser.parse_args()

    print()
    print("=" * 60)
    print("  [*] Sentinal-Fuzz Web Interface")
    print("=" * 60)
    print(f"  Open in browser: http://{args.host}:{args.port}")
    print("=" * 60)
    print()

    uvicorn.run(
        "sentinal_fuzz.web.app:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
