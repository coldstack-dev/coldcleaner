import os


if os.name == 'nt':
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class Overlapped(ctypes.Structure):
        _fields_ = [('internal', ctypes.c_size_t), ('internal_high', ctypes.c_size_t),
                    ('offset', wintypes.DWORD), ('offset_high', wintypes.DWORD),
                    ('event', wintypes.HANDLE)]

    lock_file = ctypes.WinDLL('kernel32', use_last_error=True).LockFileEx
    lock_file.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                          wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(Overlapped)]
    lock_file.restype = wintypes.BOOL

    def lock(stream, *, shared=False, blocking=True):
        flags = (0 if shared else 2) | (0 if blocking else 1)
        position = Overlapped(offset_high=1)
        if not lock_file(msvcrt.get_osfhandle(stream.fileno()), flags, 0, 1, 0, ctypes.byref(position)):
            error = ctypes.get_last_error()
            if error == 33:
                raise BlockingIOError('file lock is held')
            raise ctypes.WinError(error)
else:
    import fcntl

    def lock(stream, *, shared=False, blocking=True):
        flags = fcntl.LOCK_SH if shared else fcntl.LOCK_EX
        fcntl.flock(stream, flags | (0 if blocking else fcntl.LOCK_NB))
