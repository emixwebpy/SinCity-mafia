import logging


admin_logger = logging.getLogger('admin_actions')
admin_logger.setLevel(logging.INFO)
fh = logging.FileHandler('admin_actions.log')
admin_logger.addHandler(fh)