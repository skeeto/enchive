#if !defined(W32_COMPAT_H) && defined(_WIN32)
#define W32_COMPAT_H

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <windows.h>

#ifdef _MSC_VER
#  pragma comment(lib, "advapi32.lib")
#endif

typedef SSIZE_T ssize_t;
typedef unsigned mode_t;

#define O_CREAT   (1u << 0)
#define O_RDONLY  (1u << 1)
#define O_WRONLY  (1u << 2)
#define O_RDWR    (1u << 3)

#define ECHO    1
#define TCSANOW 0
struct termios {
    int c_lflag;
};

enum w32_fd {
    FD_NONE,
    FD_STDIN,
    FD_STDOUT,
    FD_STDERR,
    FD_URANDOM,
    FD_TTY,
    FD_FILE
};

static struct {
    enum w32_fd type;
    union {
        HANDLE file;
        HCRYPTPROV urandom;
        struct {
            HANDLE in;
            HANDLE out;
        } con;
    } d;
} w32_fds[8] = {
    {FD_STDIN,  {INVALID_HANDLE_VALUE}},
    {FD_STDOUT, {INVALID_HANDLE_VALUE}},
    {FD_STDERR, {INVALID_HANDLE_VALUE}}
};

static int
open(const char *pathname, int flags, ...)
{
    int fd = -1;

    size_t i;
    for (i = 0; fd < 0 && i < sizeof(w32_fds) / sizeof(*w32_fds); i++)
        if (w32_fds[i].type == FD_NONE)
            fd = i;
    if (fd == -1) {
        errno = EMFILE;
        return -1;
    }

    if (strcmp(pathname, "/dev/urandom") == 0) {
        DWORD type = PROV_RSA_FULL;
        DWORD flag = CRYPT_VERIFYCONTEXT | CRYPT_SILENT;
        HCRYPTPROV *h = &w32_fds[fd].d.urandom;
        if (!CryptAcquireContext(h, 0, 0, type, flag)) {
            errno = EACCES;
            return -1;
        }
        assert(flags == O_RDONLY);
        w32_fds[fd].type = FD_URANDOM;
        return fd;
    } else if (strcmp(pathname, "/dev/tty") == 0) {
        DWORD access = GENERIC_READ | GENERIC_WRITE;
        DWORD disp = OPEN_EXISTING;
        DWORD flag = FILE_ATTRIBUTE_NORMAL;
        HANDLE in = CreateFile("CONIN$", access, 0, 0, disp, flag, 0);
        HANDLE out = CreateFile("CONOUT$", access, 0, 0, disp, flag, 0);
        if (in == INVALID_HANDLE_VALUE) {
            CloseHandle(out);
            errno = ENOENT;
            return -1;
        }
        if (out == INVALID_HANDLE_VALUE) {
            CloseHandle(in);
            errno = ENOENT;
            return -1;
        }
        assert(flags == O_RDWR);
        w32_fds[fd].d.con.in = in;
        w32_fds[fd].d.con.out = out;
        w32_fds[fd].type = FD_TTY;
        return fd;
    } else {
        HANDLE h;
        DWORD access;
        DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        DWORD disp;
        DWORD flag = FILE_ATTRIBUTE_NORMAL;

        if (flags & O_CREAT)
            disp = CREATE_ALWAYS;
        else
            disp = OPEN_EXISTING;

        if (flags & O_RDWR)
            access = GENERIC_READ | GENERIC_WRITE;
        else if (flags & O_RDONLY)
            access = GENERIC_READ;
        else if (flags & O_WRONLY)
            access = GENERIC_WRITE;
        else
            abort();

        h = CreateFile(pathname, access, share, 0, disp, flag, 0);
        if (h == INVALID_HANDLE_VALUE) {
            errno = EACCES;
            return -1;
        }

        w32_fds[fd].d.file = h;
        w32_fds[fd].type = FD_FILE;
        return fd;
    }
}

static int
close(int fd)
{
    switch (w32_fds[fd].type) {
        case FD_NONE: {
            abort();
        } break;
        case FD_STDIN:
        case FD_STDOUT:
        case FD_STDERR: {
            abort(); /* unimplemented */
        } break;
        case FD_URANDOM: {
            CryptReleaseContext(w32_fds[fd].d.urandom, 0);
        } break;
        case FD_TTY: {
            CloseHandle(w32_fds[fd].d.con.in);
            CloseHandle(w32_fds[fd].d.con.out);
        } break;
        case FD_FILE: {
            CloseHandle(w32_fds[fd].d.file);
        } break;
    }
    w32_fds[fd].type = FD_NONE;
    return 0;
}

static ssize_t
read(int fd, void *buf, size_t len)
{
    switch (w32_fds[fd].type) {
        case FD_NONE: {
            abort();
        }
        case FD_STDIN: {
            if (w32_fds[fd].d.file == INVALID_HANDLE_VALUE) {
                DWORD mode;
                w32_fds[fd].d.file = GetStdHandle(STD_INPUT_HANDLE);
                assert(!GetConsoleMode(w32_fds[fd].d.file, &mode));
            }
        } /* FALLTHROUGH */
        case FD_FILE: {
            DWORD actual;
            HANDLE in = w32_fds[fd].d.file;
            if (!ReadFile(in, buf, len, &actual, 0)) {
                DWORD error = GetLastError();
                if (error == ERROR_BROKEN_PIPE)
                    return 0; /* actually an EOF */
                errno = EIO;
                return -1;
            }
            return actual;
        } break;
        case FD_STDOUT:
        case FD_STDERR: {
            abort();
        } break;
        case FD_URANDOM: {
            if (!CryptGenRandom(w32_fds[fd].d.urandom, len, buf)) {
                errno = EIO;
                return -1;
            }
            return len;
        }
        case FD_TTY: {
            DWORD actual;
            BOOL r = ReadConsole(w32_fds[fd].d.con.in, buf, len, &actual, 0);
            if (!r) {
                errno = EIO;
                return -1;
            }
            return actual;
        }
    }
    abort();
}

static ssize_t
write(int fd, const void *buf, size_t len)
{
    switch (w32_fds[fd].type) {
        case FD_URANDOM:
        case FD_NONE: {
            abort();
        }
        case FD_STDIN: {
            abort();
        } break;
        case FD_STDOUT:
        case FD_STDERR: {
            if (w32_fds[fd].d.file == INVALID_HANDLE_VALUE) {
                DWORD mode;
                if (w32_fds[fd].type == FD_STDOUT)
                    w32_fds[fd].d.file = GetStdHandle(STD_OUTPUT_HANDLE);
                else
                    w32_fds[fd].d.file = GetStdHandle(STD_ERROR_HANDLE);
                assert(!GetConsoleMode(w32_fds[fd].d.file, &mode));
            }
        } /* FALLTHROUGH */
        case FD_FILE: {
            DWORD actual;
            if (!WriteFile(w32_fds[fd].d.file, buf, len, &actual, 0)) {
                errno = EIO;
                return -1;
            }
            return actual;
        } break;
        case FD_TTY: {
            DWORD actual;
            BOOL r = WriteConsole(w32_fds[fd].d.con.out, buf, len, &actual, 0);
            if (!r) {
                errno = EIO;
                return -1;
            }
            return actual;
        }
    }
    abort();
}

static int
tcgetattr(int fd, struct termios *s)
{
    assert(w32_fds[fd].type == FD_TTY);
    s->c_lflag = 1;
    return 0;
}

static int
tcsetattr(int fd, int actions, struct termios *s)
{
    DWORD orig;
    HANDLE in = w32_fds[fd].d.con.in;

    assert(w32_fds[fd].type == FD_TTY);
    assert(actions == TCSANOW);
    if (GetConsoleMode(in, &orig)) {
        if (s->c_lflag)
            SetConsoleMode(in, orig | ENABLE_ECHO_INPUT);
        else
            SetConsoleMode(in, orig & ~ENABLE_ECHO_INPUT);
    }
    return 0;
}

#if 0
static int
mkdir(const char *pathname, mode_t mode)
{
    (void)mode;
    if (CreateDirectory(pathname, 0))
        return 0;
    switch (GetLastError()) {
        case ERROR_ALREADY_EXISTS: {
            errno = EEXIST;
        } break;
        case ERROR_PATH_NOT_FOUND: {
            errno = ENOENT;
        } break;
        default: {
            errno = EFAULT;
        }
    }
    return -1;
}
#endif

#endif
