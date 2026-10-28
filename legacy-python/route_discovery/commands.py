import asyncio


class BackendError(RuntimeError):
    pass


async def run(*args, timeout=5.0):
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError as exc:
        raise BackendError(str(exc)) from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except (TimeoutError, asyncio.CancelledError) as exc:
        if process.returncode is None:
            process.kill()
        await process.communicate()
        if isinstance(exc, asyncio.CancelledError):
            raise
        raise BackendError(f"{args[0]} timed out") from exc
    output = stdout.decode(errors="replace")
    if process.returncode:
        raise BackendError(f"{args[0]} exited {process.returncode}: {stderr.decode(errors='replace').strip()} {output.strip()}")
    return output
