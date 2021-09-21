import logging
from app.utility.base_parser import BaseParser


class Parser(BaseParser):

    def parse(self, blob):
        for l in self.line(blob):
            if 'FullyQualifiedErrorId' in l:
                log = logging.getLogger('parsing_svc')
                log.warning('This ability failed for some reason. Manually updating the link to report a failed state.')
                return 418  # Universal Teapot error code
        return []