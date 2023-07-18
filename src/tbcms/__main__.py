import argparse

from tbcms import server


def handle_args() -> argparse.Namespace:
    """Handle command line arguments

    Returns:
        argparse.Namespace: The parsed arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=80, help="Port to listen on")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to listen on")
    parser.add_argument(
        "--presents",
        type=str,
        help="Path to presents file",
    )

    return parser.parse_args()


args = handle_args()
debug = args.debug
port = args.port
host = args.host
presents = args.presents
server.run(debug=debug, port=port, host=host, path=presents)
