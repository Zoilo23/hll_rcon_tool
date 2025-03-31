from rcon.connection import HLLConnectionV2, ContentBody, ServerInformationCommands
from rcon.settings import SERVER_INFO

import os

from logging import getLogger

logger = getLogger(__name__)

if __name__ == "__main__":
    c = HLLConnectionV2()

    c.connect(SERVER_INFO["host"], SERVER_INFO["port"], SERVER_INFO["password"])

    resp = c.request(
        "ServerInformation", body=ContentBody(name=ServerInformationCommands.SESSION)
    )
    logger.info("Response=%s", resp)
