from __future__ import annotations

import asyncio
import os
import sys

from dotenv import load_dotenv
from mcp.server import Server
from mcp.server.stdio import stdio_server

load_dotenv()

OPTIX_API_URL = os.environ.get("OPTIX_API_URL", "https://optixthreatintelligence.co.uk")
OPTIX_API_KEY = os.environ.get("OPTIX_API_KEY", "")


async def main() -> None:
    if not OPTIX_API_KEY:
        print(
            "Error: OPTIX_API_KEY environment variable is required for stdio mode.",
            file=sys.stderr,
        )
        sys.exit(1)

    from auth import _validate_key_with_optix, current_api_key, current_auth
    from exceptions import OptixAuthError
    from prompts import register_prompts
    from tools import register_tools

    try:
        auth_ctx = await _validate_key_with_optix(OPTIX_API_KEY)
    except OptixAuthError as exc:
        print(f"Error: OPTIX API key validation failed — {exc.message}", file=sys.stderr)
        sys.exit(1)

    current_api_key.set(OPTIX_API_KEY)
    current_auth.set(auth_ctx)

    mcp_server = Server("optix-mcp")
    register_tools(mcp_server)
    register_prompts(mcp_server)

    async with stdio_server() as (read_stream, write_stream):
        await mcp_server.run(
            read_stream,
            write_stream,
            mcp_server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
