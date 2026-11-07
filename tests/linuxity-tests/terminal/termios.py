"""termios: line discipline modes, control characters, speeds, flushing."""
import os
import pty
import select
import termios
import tty

from lxt import check, eq, test
from terminal._pty import read_until


def pair():
    m, s = pty.openpty()
    return m, s


@test
def canonical_vs_raw():
    """Canonical mode waits for a line and edits it; raw mode delivers bytes now."""
    m, s = pair()
    a = termios.tcgetattr(s)
    a[3] &= ~termios.ECHO
    termios.tcsetattr(s, termios.TCSANOW, a)
    os.write(m, b"abc")
    eq(select.select([s], [], [], 0.2)[0], [], "canonical read ready before newline")
    os.write(m, b"\x7fd\n")            # backspace erases c
    eq(os.read(s, 100), b"abd\n", "line after VERASE")
    os.write(m, b"junk\x15ok\n")       # ^U kills the line
    eq(os.read(s, 100), b"ok\n", "VKILL")
    tty.setraw(s)
    os.write(m, b"x")
    check(select.select([s], [], [], 2)[0], "raw byte not ready")
    eq(os.read(s, 10), b"x", "raw read")
    os.write(m, b"\x03\x7f")
    eq(os.read(s, 10), b"\x03\x7f", "raw passes control bytes through")
    return "line edit, VERASE, VKILL, raw"


@test
def echo_and_onlcr():
    """ECHO echoes input to the master; ONLCR turns \\n into \\r\\n on output."""
    m, s = pair()
    os.write(m, b"hi\n")
    eq(read_until(m, b"hi\r\n", 3)[-4:], b"hi\r\n", "echo with ONLCR")
    os.read(s, 10)
    a = termios.tcgetattr(s)
    a[1] &= ~termios.ONLCR
    termios.tcsetattr(s, termios.TCSANOW, a)
    os.write(s, b"a\nb")
    eq(read_until(m, b"a\nb", 3)[-3:], b"a\nb", "no ONLCR")
    return "echo, ONLCR on/off"


@test
def attributes_roundtrip():
    """tcsetattr values read back: flags, VMIN/VTIME, control chars, speeds."""
    m, s = pair()
    a = termios.tcgetattr(s)
    a[0] |= termios.IXON
    a[3] &= ~(termios.ICANON | termios.ECHO)
    a[6][termios.VMIN] = 3
    a[6][termios.VTIME] = 7
    a[6][termios.VINTR] = b"\x07"
    a[4] = a[5] = termios.B9600
    termios.tcsetattr(s, termios.TCSADRAIN, a)
    b = termios.tcgetattr(s)
    eq(b[0] & termios.IXON, termios.IXON, "iflag")
    eq(b[3] & (termios.ICANON | termios.ECHO), 0, "lflag")
    eq((b[6][termios.VMIN], b[6][termios.VTIME]), (3, 7), "VMIN/VTIME")
    eq(b[6][termios.VINTR], b"\x07", "VINTR")
    eq((b[4], b[5]), (termios.B9600, termios.B9600), "speeds")
    eq(termios.tcgetattr(m)[6][termios.VINTR], b"\x07", "the master sees the same termios")
    # with VTIME 0, read readiness waits for VMIN bytes
    b[6][termios.VTIME] = 0
    termios.tcsetattr(s, termios.TCSANOW, b)
    os.write(m, b"12")
    eq(select.select([s], [], [], 0.2)[0], [], "VMIN=3 isn't satisfied by 2 bytes")
    os.write(m, b"3")
    eq(os.read(s, 10), b"123", "VMIN read")
    return "iflag, lflag, VMIN/VTIME, VINTR, B9600"


@test
def flush_and_drain():
    """tcflush drops queued input; tcdrain and tcsendbreak return."""
    m, s = pair()
    tty.setraw(s)
    os.write(m, b"stale")
    check(select.select([s], [], [], 2)[0], "input never arrived")
    termios.tcflush(s, termios.TCIFLUSH)
    eq(select.select([s], [], [], 0.2)[0], [], "input left after TCIFLUSH")
    os.write(s, b"out")
    termios.tcdrain(s)
    termios.tcsendbreak(s, 0)
    eq(read_until(m, b"out", 3)[-3:], b"out", "output after tcdrain")
    return "TCIFLUSH, tcdrain, tcsendbreak"
