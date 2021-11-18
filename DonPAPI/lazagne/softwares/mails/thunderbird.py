from DonPAPI.lazagne.config.module_info import ModuleInfo
from DonPAPI.lazagne.softwares.browsers.mozilla import Mozilla


class Thunderbird(Mozilla):

    def __init__(self):
        self.path = u'{APPDATA}\\Thunderbird'
        ModuleInfo.__init__(self, 'Thunderbird', 'mails')
