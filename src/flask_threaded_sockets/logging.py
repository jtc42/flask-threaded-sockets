from logging import getLogger, StreamHandler, getLoggerClass, Formatter, DEBUG

def create_logger(name, handlers=None):
    """Created a logger object from a list of log handlers

    Args:
        name (str): Name for the logger
        handlers ([logging.Handler], optional): [List of log handlers]. Defaults to None.

    Returns:
        [logging.Logger]: Logger object containing the passed handlers
    """
    if not handlers:
        handlers = ()

    logger = getLogger(name)

    for handler in handlers:
        logger.addHandler(handler)

    return logger
