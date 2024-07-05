import logging
from logging import LogRecord
from logging.handlers import RotatingFileHandler
import os.path
import sys
import re
from donpapi.lib.paths import DPP_LOG_FILE_PATH
from termcolor import colored
from datetime import datetime
from rich.text import Text
from rich.logging import RichHandler
from rich.console import Console

donpapi_console = Console(soft_wrap=True, tab_size=4)

class DonPAPIAdapter(logging.LoggerAdapter):
    def __init__(self, extra=None):
        self.donpapi_console = donpapi_console
        logging.basicConfig(
            format="%(message)s",
            datefmt="[%X]",
            handlers=[
                RichHandler(
                    console=self.donpapi_console,
                    rich_tracebacks=True,
                    tracebacks_show_locals=False,
                    markup=True
                )
            ],
        )
        self.logger = logging.getLogger("donpapi")
        self.extra = extra
        self.output_file = None

        logging.getLogger("impacket").disabled = True
        logging.getLogger("dploot").disabled = True
        # logging.getLogger("werkzeug").disabled = True

    def format(self, msg, *args, **kwargs):
        """
        Format msg for output if needed
        This is used instead of process() since process() applies to _all_ messages, including debug calls
        """
        if self.extra is None:
            return f"{msg}", kwargs

        host = colored(self.extra["host"], "green", attrs=["bold"])
        _ = colored(self.extra['hostname'] if self.extra['hostname'] else '', "green", attrs=["bold"])

        return (
            f"[{host}] {msg}",
            kwargs,
        )

    def display(self, msg, *args, **kwargs):
        """
        Display text to console
        """

        msg, kwargs = self.format(f"{colored('[+]', 'blue', attrs=['bold'])} {msg}", kwargs)
        text = Text.from_ansi(msg)
        self.donpapi_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    def secret(self, msg, secret_tag, color='green', *args, **kwargs):
        """
        Print secrets
        """
        secret_tag_printed = f"[{secret_tag}]"
        msg, kwargs = self.format(f"{colored('[$]', color, attrs=['bold'])} {colored(secret_tag_printed, 'yellow', attrs=['bold'])} {colored(msg, 'yellow', attrs=['bold'])}", kwargs)
        text = Text.from_ansi(msg)
        self.donpapi_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    def verbose(self, msg, *args, **kwargs):
        """
        Prints a completely yellow highlighted message to the user
        """
        if donpapi_logger.logger.level > logging.INFO:
            return
        msg, kwargs = self.format(f"{colored('[*]', 'yellow', attrs=['bold'])} {msg}", kwargs)
        text = Text.from_ansi(msg)
        self.donpapi_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    def fail(self, msg, color='red', *args, **kwargs):
        """
        Prints a failure (may or may not be an error) - e.g. login creds didn't work
        """
        msg, kwargs = self.format(f"{colored('[-]', color, attrs=['bold'])} {msg}", kwargs)
        text = Text.from_ansi(msg)
        self.donpapi_console.print(text, *args, **kwargs)
        self.log_console_to_file(text, *args, **kwargs)

    def log_console_to_file(self, text, *args, **kwargs):
        """
        If debug or info logging is not enabled, we still want display/success/fail logged to the file specified,
        so we create a custom LogRecord and pass it to all the additional handlers (which will be all the file handlers
        """
        if self.logger.getEffectiveLevel() >= logging.INFO:
            # will be 0 if it's just the console output, so only do this if we actually have file loggers
            if len(self.logger.handlers):
                try:
                    for handler in self.logger.handlers:
                        handler.handle(
                            LogRecord(
                                "donpapi",
                                20,
                                "",
                                kwargs,
                                msg=text,
                                args=args,
                                exc_info=None,
                            )
                        )
                except Exception as e:
                    self.logger.fail(f"Issue while trying to custom print handler: {e}")

    def add_file_log(self, log_file=DPP_LOG_FILE_PATH):
        file_formatter = TermEscapeCodeFormatter("%(asctime)s - %(levelname)s - %(message)s")
        log_file = DPP_LOG_FILE_PATH if log_file is None else log_file
        file_creation = False

        if not os.path.isfile(log_file):
            open(log_file, "x")
            file_creation = True

        file_handler = RotatingFileHandler(log_file, maxBytes=100000)

        with file_handler._open() as f:
            if file_creation:
                f.write("[%s]> %s\n\n" % (datetime.now().strftime("%d-%m-%Y %H:%M:%S"), " ".join(sys.argv)))
            else:
                f.write("\n[%s]> %s\n\n" % (datetime.now().strftime("%d-%m-%Y %H:%M:%S"), " ".join(sys.argv)))

        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        self.logger.debug(f"Added file handler: {file_handler}")

class TermEscapeCodeFormatter(logging.Formatter):
    """A class to strip the escape codes for logging to files"""

    def __init__(self, fmt=None, datefmt=None, style="%", validate=True):
        super().__init__(fmt, datefmt, style, validate)

    def format(self, record):
        escape_re = re.compile(r"\x1b\[[0-9;]*m")
        record.msg = re.sub(escape_re, "", str(record.msg))
        return super().format(record)

donpapi_logger = DonPAPIAdapter()