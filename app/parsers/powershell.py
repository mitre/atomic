import logging
from app.utility.base_parser import BaseParser, PARSER_SIGNALS_FAILURE


class Parser(BaseParser):

    def parse(self, blob):
        for l in self.line(blob):
            if 'FullyQualifiedErrorId' in l:
                log = logging.getLogger('parsing_svc')
                log.warning('This ability failed for some reason. Manually updating the link to report a failed state.')
                return [PARSER_SIGNALS_FAILURE]
        return []