import asyncio
import sys

LOADED_MODULES = """
import importlib
import pkgutil
import sys

import sotto.crypto

for module in pkgutil.walk_packages(sotto.crypto.__path__, "sotto.crypto."):
    importlib.import_module(module.name)
print(*sorted(sys.modules), sep="\\n")
"""


async def test_crypto_loads_neither_websockets_nor_sqlite3() -> None:
    interpreter = await asyncio.create_subprocess_exec(
        sys.executable, "-c", LOADED_MODULES, stdout=asyncio.subprocess.PIPE
    )

    try:
        async with asyncio.timeout(60):
            output, _ = await interpreter.communicate()
    finally:
        if interpreter.returncode is None:
            interpreter.kill()
            await interpreter.wait()

    loaded = output.decode().split()
    packages = {name.partition(".")[0] for name in loaded}
    assert interpreter.returncode == 0
    assert "sotto.crypto.identity" in loaded
    assert packages.isdisjoint({"websockets", "sqlite3", "_sqlite3"})
