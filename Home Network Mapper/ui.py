"""
UI Utilities for Terminal Applications
Provides colorful, modern Unicode-styled boxes, banners, menus, and result cards.
"""

import re
import sys
import time
import threading

COLORS = {
    "cyan": "\033[96m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "red": "\033[91m",
    "white": "\033[97m",
    "gray": "\033[90m",
}
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def get_color(color_name: str) -> str:
    return COLORS.get(color_name.lower(), "\033[96m")


def strip_ansi(text: str) -> str:
    """Removes ANSI color/style escape sequences from a string for accurate width calculation."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def pad_line(content: str, width: int) -> str:
    """Pads a line of text accounting for hidden ANSI escape sequences."""
    vis_len = len(strip_ansi(content))
    padding = max(0, width - 4 - vis_len)
    return f"  {content}{' ' * padding}  "


def print_banner(
    title: str, lines: list[str], color: str = "cyan", align: str = "left"
):
    """Prints a styled top banner box."""
    c = get_color(color)
    content_width = max(len(title), *(len(line) for line in lines))
    width = max(content_width + 6, 60)

    print(f"\n{c}╭{'─' * width}╮{RESET}")
    print(f"{c}│{BOLD}{title.center(width)}{RESET}{c}│{RESET}")
    print(f"{c}├{'─' * width}┤{RESET}")
    for line in lines:
        if align == "center":
            formatted = line.center(width - 4)
        else:
            formatted = line.ljust(width - 4)
        print(f"{c}│{RESET}  {formatted}  {c}│{RESET}")
    print(f"{c}╰{'─' * width}╯{RESET}")


def print_menu(title: str, options: list[tuple[str, str]], color: str = "cyan"):
    """Prints a structured menu selection block."""
    c = get_color(color)
    print(f"\n{c}┌── {BOLD}{title}{RESET}")
    for key, desc in options:
        print(f"{c}│{RESET}   [{c}{BOLD}{key}{RESET}] {desc}")
    print(f"{c}└──{RESET}")


def print_result_box(title: str, fields: list[tuple[str, str]], color: str = "green"):
    """Prints a clean result box with key-value fields."""
    c = get_color(color)
    rendered_lines = [f"{k.ljust(11)}: {v}" for k, v in fields]
    max_len = max(len(title) + 4, *(len(l) for l in rendered_lines))
    width = max(max_len + 4, 55)

    print(f"\n{c}╭── {BOLD}{title}{RESET} {c}{'─' * (width - len(title) - 5)}╮{RESET}")
    for line in rendered_lines:
        print(f"{c}│{RESET}  {line.ljust(width - 4)}  {c}│{RESET}")
    print(f"{c}╰{'─' * width}╯{RESET}")



 
 
class Spinner:
    """
    Animated terminal loading spinner using a daemon background thread.
    Usage:
        with Spinner("Scanning subnet...", color="cyan"):
            run_long_task()
    """
    FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    def __init__(self, message: str = "Loading...", color: str = "cyan", show_elapsed: bool = True):
        self.message = message
        self.color = color
        self.show_elapsed = show_elapsed
        self._stop_event = threading.Event()
        self._thread = None
        self.start_time = 0.0

    def _spin(self):
        c = get_color(self.color)
        idx = 0
        while not self._stop_event.is_set():
            frame = self.FRAMES[idx % len(self.FRAMES)]
            elapsed = time.time() - self.start_time
            elapsed_str = f" {DIM}({elapsed:.1f}s){RESET}" if self.show_elapsed else ""
            line = f"\r  {c}{BOLD}{frame}{RESET} {self.message}{elapsed_str}  "
            sys.stdout.write(line)
            sys.stdout.flush()
            idx += 1
            time.sleep(0.08)

    def start(self):
        self.start_time = time.time()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self, success_message: str | None = None, color: str = "green"):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=0.5)
        # Clear the spinner line
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        if success_message:
            c = get_color(color)
            elapsed = time.time() - self.start_time
            print(f"  {c}{BOLD}✔{RESET} {success_message} {DIM}(took {elapsed:.1f}s){RESET}\n")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


