# credvault/memory.py - FIXED VERSION
import ctypes
import platform
import threading
import time

# Platform-specific memory locking
if platform.system() == "Windows":
    from ctypes import wintypes

    kernel32 = ctypes.windll.kernel32

    VirtualLock = kernel32.VirtualLock
    VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    VirtualLock.restype = wintypes.BOOL

    VirtualUnlock = kernel32.VirtualUnlock
    VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    VirtualUnlock.restype = wintypes.BOOL

    def mlock(addr: int, length: int) -> bool:
        try:
            # Convert length to c_size_t for Windows API
            return bool(VirtualLock(addr, ctypes.c_size_t(length)))
        except:
            return False  # Return False on error

    def munlock(addr: int, length: int) -> bool:
        try:
            return bool(VirtualUnlock(addr, ctypes.c_size_t(length)))
        except:
            return False

else:
    # POSIX systems (Linux, macOS)
    libc = ctypes.CDLL(None)

    if platform.system() == "Darwin":
        # macOS
        libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    else:
        # Linux
        libc.mlock.restype = ctypes.c_int
        libc.munlock.restype = ctypes.c_int

    def mlock(addr: int, length: int) -> bool:
        try:
            return libc.mlock(addr, length) == 0
        except:
            return False

    def munlock(addr: int, length: int) -> bool:
        try:
            return libc.munlock(addr, length) == 0
        except:
            return False


def lock_memory(buffer: bytearray) -> bool:
    """
    Lock a bytearray in memory to prevent swapping.
    Returns: True if successful, False otherwise
    """
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        return mlock(addr, len(buffer))
    except:
        return False


def unlock_memory(buffer: bytearray) -> bool:
    """
    Unlock a bytearray from memory.
    Returns: True if successful, False otherwise
    """
    try:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        return munlock(addr, len(buffer))
    except:
        return False


def disable_core_dumps():
    """Disable core dumps for the current process"""
    try:
        if platform.system() != "Windows":
            import resource

            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except:
        pass


def secure_alloc(size: int) -> bytearray:
    """
    Allocate memory and try to lock it
    Returns: bytearray containing secured memory
    """
    # Create bytearray with desired size
    buffer = bytearray(size)

    try:
        # Get memory address
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))

        # Try to lock memory (may fail without admin privileges on Windows)
        mlock(addr, size)
    except Exception:
        # Don't crash if memory locking fails
        # Continue without locking - better than not working at all
        pass

    return buffer


def secure_free(buffer: bytearray):
    """
    Securely zero and unlock memory
    """
    if not buffer:
        return

    # Zero the memory
    for i in range(len(buffer)):
        buffer[i] = 0

    try:
        # Try to unlock
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buffer))
        munlock(addr, len(buffer))
    except:
        pass

    # Clear reference
    del buffer


def zeroize_buffer(buffer: bytearray):
    """Securely zeroize a buffer"""
    for i in range(len(buffer)):
        buffer[i] = 0


def secure_delayed_clear(data: str, delay_seconds: int = 10):
    """
    Schedule secure clearing of data after delay
    Useful for clipboard clearance
    """

    def clear_data():
        time.sleep(delay_seconds)

        # Overwrite the string in memory
        import pyperclip

        pyperclip.copy("")  # Clear clipboard

    thread = threading.Thread(target=clear_data, daemon=True)
    thread.start()


# Disable core dumps on import
disable_core_dumps()
