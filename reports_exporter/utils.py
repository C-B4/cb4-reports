import sys


def isEmpty(s):
    if (s is None) or (len(s) <= 0):
        return True
    else:
        return False


def die(msg=None, rc=1):
        """
        Cleanly exits the program with an error message
        """

        if msg:
            sys.stderr.write(msg)
            sys.stderr.write("\n")
            sys.stderr.flush()

        sys.exit(rc)


def buildUrlQueryParams(queryParams):
    if isEmpty(queryParams):
        return None

    nvPairs = []
    for key, value in queryParams.items():
        if isinstance(value, (int, float, bool)):
            value = str(value)
        nvPairs.append("%s=%s" % (key, value))

    return "&".join(nvPairs)

