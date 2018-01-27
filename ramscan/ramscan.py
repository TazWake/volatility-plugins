# RAMSCAN
# A slightly faster version of MALFIND which checks
# command lines and VAD blocks
# This plugin has been created to help learn volatility plugins
# and its functionality will change over time.
# Ramscan extracts process name, PID and parent PID, and command line.
# Each process VAD is checked and entries with Read/Write/Execute are marked
# as suspicious
#
# Authors:
# Taz Wake (t.wake@halkynconsulting.co.uk)
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.

import volatility.plugins.common as common
import volatility.utils as utils
import volatility.win32 as win32

from volatility.renderers import TreeGrid


class RamScan(common.AbstractWindowsCommand):
    '''List processes, PID, PPID, Command Line, VAD Status'''

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)
        return tasks

    def generator(self, data):
        cmdline = ""
        vf = ""
    for task in data:
            if task.Peb:
                cmdline = "{0}".format(str(task.Peb.ProcessParameters.CommandLine or '')).strip()
            process_space = task.get_process_address_space()
            for vad in task.VadRoot.traverse():
                data = process_space.read(vad.Start, 1024)
                if vad.u.VadFlags.CommitCharge.v() > 30:
                    if vad.u.VadFlags.Protection.v() == 6:
                        vf = "Suspicious RWX VAD"
            yield (0, [
                str(task.ImageFileName),
                int(task.UniqueProcessId),
                int(task.InheritedFromUniqueProcessId),
                str(cmdline),
                str(vf),
            ])

    def unified_output(self, data):
        tree = [
            ("Name", str),
            ("PID", int),
            ("Parent", int),
            ("Command Line", str),
            ("VAD", str),
        ]

        return TreeGrid(tree, self.generator(data))
