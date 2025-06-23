import logging
from pathlib import Path

Path("src/logs").mkdir(parents=True, exist_ok=True)

class InfoFilter(logging.Filter):
    def filter(self, record):
        return getattr(record, "log_info", False)

logger = logging.getLogger("project_logger")
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")

error_handler = logging.FileHandler("src/logs/errors.log", encoding="UTF-8")
error_handler.setLevel(logging.ERROR)
error_handler.setFormatter(formatter)

info_handler = logging.FileHandler("src/logs/info.log", encoding="UTF-8")
info_handler.setLevel(logging.INFO)
info_handler.addFilter(InfoFilter())
info_handler.setFormatter(formatter)

logger.addHandler(error_handler)
logger.addHandler(info_handler)