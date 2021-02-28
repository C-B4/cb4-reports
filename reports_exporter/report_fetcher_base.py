import datetime
import os
import urllib.error
import urllib.request
from tempfile import gettempdir

import requests

from reports_exporter.utils import isEmpty


class ReportFetcherBase:
    def __init__(self, logger, args, file_name_prefix) -> None:
        super().__init__()
        self.file_name_prefix = file_name_prefix
        self.logger = logger
        self.args = args

    def downloadReport(self, url, verb, headersMap, reqData):
        if headersMap is None:
            headersMap = {}

        dataBytes = None
        if not isEmpty(reqData):
            dataBytes = bytes(reqData, 'utf-8')
            headersMap["Content-Length"] = str(len(dataBytes))

        try:
            # InsecureRequestWarning: Unverified HTTPS request is being made.
            requests.packages.urllib3.disable_warnings()

            self.logger.debug("url: %s, header:%s, data: %s" % (url, headersMap, dataBytes))
            connTimeout = self.args.get("connectTimeout", 15)
            rspTimeout = self.args.get("responseTimeout", 3000)
            rsp = requests.request(verb, url, headers=headersMap,
                data=dataBytes, verify=False, timeout=(connTimeout, rspTimeout))
            statusCode = rsp.status_code
            if (statusCode < 200) or (statusCode >= 400):
                raise urllib.error.HTTPError(url, statusCode, "Failed: %d" % statusCode, rsp.headers, None)

            filePath = self.resolveOutputFilePath()
            text_file = open(filePath, "wb")
            for chunk in rsp.iter_content(chunk_size=1024):
                text_file.write(chunk)

            text_file.close()
        except urllib.error.HTTPError as err:
            self.logger.error("Failed (%d %s) to invoke %s %s" % (err.code, err.msg, verb, url))
            raise err
        except urllib.error.URLError as err:
            self.logger.error("Some unknown error for %s %s: %s" % (verb, url, err.reason))
            raise err

    def resolveOutputFilePath(self):
        filePath = self.args.get("file", None)
        if not isEmpty(filePath):
            filePath = self.resolvePathVariables(filePath)
            if os.path.isabs(filePath):
                print("report exported: {}".format(filePath))
                return filePath

        dirPath = self.args.get("dir", None)
        if not isEmpty(dirPath):
            dirPath = self.resolvePathVariables(dirPath)
        else:
            dirPath = gettempdir()


        if isEmpty(filePath):
            today = datetime.datetime.utcnow()
            filePath = "%s_%s.csv" % (self.file_name_prefix, today.strftime("%Y%m%d_%H%M"))


        if not os.path.isabs(dirPath):
            dirPath = os.path.abspath(dirPath)

        path = os.path.join(dirPath, filePath)
        print("Report exported to: {}".format(path))
        return path

    def resolvePathVariables(self, path):
        """
        Expands ~/xxx and ${XXX} variables
        """
        if isEmpty(path):
            return path

        path = os.path.expanduser(path)
        path = os.path.expandvars(path)
        return path