import sys
import datetime
import threading
import traceback

from reports_exporter.utils import die


class LogLevel(object):
    def __init__(self, name, value):
        self.levelName = name
        self.levelValue = value

    @property
    def name(self):
        return self.levelName

    @name.setter
    def name(self, value):
        raise NotImplementedError("Log level name is immutable")

    @property
    def value(self):
        return self.levelValue

    @value.setter
    def value(self, number):
        raise NotImplementedError("Log level value is immutable")

    def __str__(self):
        return "%s[%s]" % (self.name, str(self.value))


class Logger(object):
    # Because of some Python limitations we need to define these here
    OFF = LogLevel('OFF', 10000)
    ERROR = LogLevel('ERROR', 1000)
    WARNING = LogLevel('WARNING', 900)
    INFO = LogLevel('INFO', 800)
    DEBUG = LogLevel('DEBUG', 700)
    TRACE = LogLevel('TRACE', 600)
    ALL = LogLevel('ALL', 0)
    LEVELS = [OFF, ERROR, WARNING, INFO, DEBUG, TRACE, ALL]

    def __init__(self, name, threshold, args):
        self.loggerName = name
        self.thresholdLevel = threshold
        self.dateTimeFormat = args.get("log-datetime-format", "%Y-%m-%d %H:%M:%S.%f")
        self.maxStackTraceDepth = args.get("log-stacktrace-depth", 10)

    @property
    def name(self):
        return self.loggerName

    @name.setter
    def name(self,value):
        raise NotImplementedError("Logger name is immutable")

    @property
    def threshold(self):
        return self.thresholdLevel

    @threshold.setter
    def threshold(self, value):
        raise NotImplementedError("Not allowed to modify threshold level for %s" % self.name)

    @property
    def errorEnabled(self):
        return self.levelEnabled(Logger.ERROR)

    @errorEnabled.setter
    def errorEnabled(self, value):
        raise NotImplementedError("Not allowed to modify ERROR enabled state for %s" % self.name)

    def error(self, msg, err=None):
        self.log(Logger.ERROR, msg, err)

    @property
    def warningEnabled(self):
        return self.levelEnabled(Logger.WARNING)

    @warningEnabled.setter
    def warningEnabled(self, value):
        raise NotImplementedError("Not allowed to modify WARNING enabled state for %s" % self.name)

    def warning(self, msg, err=None):
        self.log(Logger.WARNING, msg, err)

    @property
    def infoEnabled(self):
        return self.levelEnabled(Logger.INFO)

    @infoEnabled.setter
    def infoEnabled(self, value):
        raise NotImplementedError("Not allowed to modify INFO enabled state for %s" % self.name)

    def info(self, msg, err=None):
        self.log(Logger.INFO, msg, err)

    @property
    def debugEnabled(self):
        return self.levelEnabled(Logger.DEBUG)

    @debugEnabled.setter
    def debugEnabled(self, value):
        raise NotImplementedError("Not allowed to modify DEBUG enabled state for %s" % self.name)

    def debug(self, msg, err=None):
        self.log(Logger.DEBUG, msg, err)

    @property
    def traceEnabled(self):
        return self.levelEnabled(Logger.TRACE)

    @traceEnabled.setter
    def traceEnabled(self, value):
        raise NotImplementedError("Not allowed to modify TRACE enabled state for %s" % self.name)

    def trace(self, msg, err=None):
        self.log(Logger.TRACE, msg, err)

    def log(self, level, msg, err=None):
        if self.levelEnabled(level):
            self.appendLog(level, msg, err)

    def appendLog(self, level, msg, err=None):
        nowValue = datetime.datetime.now()
        timestamp = nowValue.strftime(self.dateTimeFormat)
        threadName = "unknown"
        thread = threading.current_thread()
        if not thread is None:
            threadName = thread.name

        if msg:
            if '\n' in msg:
                for line in msg.splitlines(False):
                    self.writeLogMessage(level, "%s %s [%s] [%s] %s" % (timestamp, threadName, level.name, self.name, line))
            else:
                self.writeLogMessage(level, "%s %s [%s] [%s] %s" % (timestamp, threadName, level.name, self.name, msg))
        if err:
            self.writeLogMessage(level, "%s %s [%s] [%s] %s: %s" % (timestamp, threadName, level.name, self.name, err.__class__.__name__, str(err)))

            if self.maxStackTraceDepth > 0:
                # TODO this doesn't quite do the job - by the time it is here, most stack trace data is gone...
                traceValue = traceback.format_exc(self.maxStackTraceDepth)
                lines = traceValue.splitlines()
                for traceLine in lines:
                    self.writeLogMessage(level, "%s %s [%s] %s %s" % (timestamp, threadName, level.name, self.name, traceLine))

            if err.__class__.__name__ == "KeyboardInterrupt":
                die("Killed by Control+C")

    def writeLogMessage(self, level, msg):
        raise NotImplementedError("%s#writeLogMessage(%s) not implemented" % (self.__class__.__name__, msg))

    def levelEnabled(self, level):
        if not level or not self.threshold:
            return False
        elif level.value >= self.threshold.value:
            return True
        else:
            return False

    def __str__(self):
        return self.name

    @staticmethod
    def fromLevelName(name):
        if (not name) or (len(name) <= 0):
            return None

        effectiveName = name.upper()
        for level in Logger.LEVELS:
            if level.name == effectiveName:
                return level

        return None

    @staticmethod
    def logHelp(logger, lines):
        if (not lines) or (len(lines) <= 0):
            return

        for line in lines:
            logger.info(line)


class StreamLogger(Logger):
    def __init__(self, name, threshold, args):
        super(StreamLogger, self).__init__(name, threshold, args)
        self.targetStream = None
        self.autoFlush = args.get("log-auto-flush", True)

    def writeLogMessage(self, level, msg):
        self.targetStream.write("%s\n" % msg)
        if self.autoFlush:
            self.targetStream.flush()


class ConsoleLogger(StreamLogger):
    def __init__(self, name, threshold, args):
        super(ConsoleLogger, self).__init__(name, threshold, args)
        target = args.get("log-console-target", "stderr").lower()
        if target == "stdout":
            self.targetStream = sys.stdout
        else:
            self.targetStream = sys.stderr


class LogFactory(object):
    def __init__(self, args):
        self.args = args
        self.threshold = Logger.fromLevelName(args.get("log-threshold", Logger.INFO.name))
        if self.threshold is None:
            self.threshold = Logger.OFF

    def getLogger(self, name):
        # TODO add support for more logger types
        return ConsoleLogger(name, self.threshold, self.args)