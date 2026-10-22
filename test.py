import asyncio
from core.http import new_session, fetch, RateLimiter
from core import fingerprint


async def main():
    fingerprint.set_default("chrome_130_win")
    session = new_session()
    try:
        status, headers, body, final = await fetch(
            session,
            "https://httpbin.org/headers",
            RateLimiter(5.0),
        )
        print(body)
    finally:
        await session.close()


asyncio.run(main())