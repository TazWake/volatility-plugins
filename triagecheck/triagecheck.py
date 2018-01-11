# Triage Check
#
# This plugin looks at some obvious signs of malicious activity and tries to highlight them. 
# The idea is to give a very quick assessment for malice. This is not an indepth check for evil.
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
#

import volatility.win32 as win32
import volatility.utils as utils
import volatility.plugins.common as common

from volatility.renderers import TreeGrid

class TriageCheck(common.AbstractWindowsCommand):
    '''Checks for obvious signs of malice'''

    def calculate(self):
        addr_space = utils.load_as(self._config)
        tasks = win32.tasks.pslist(addr_space)

        return tasks

    def generator(self, data):
        csrsscount = 0
        lsasscount = 0
        for task in data:
            response = "No obvious issues"
            holder = ""
            procname = str(task.ImageFileName)
            pid = int(task.UniqueProcessId)
            imgpath = str(task.Peb.ProcessParameters.ImagePathName)

            # Check csrss for known attacks 
            # Should only be 1 instance of csrss, running from system32
            check = "csrss.exe"
            if procname == check:
            # if task.ImageFilename == "csrss.exe":
                csrsscount = csrsscount+1
                # Check number of instances
                if csrsscount > 1:
                    # multiple csrss found
                    response = "Multiple instances of CSRSS found"
                # Check location
                #imgpath = str(task.Peb.ProcessParameters.ImagePathName)
                path = str("\system32\csrss.exe")
                if path in imgpath.lower():
                   # valid path
                   holder = "valid"
                else:
        	    # invalid path
                    response = "CSRSS launched from invalid path"                
            
            # Check for CSRSS impersonation
            check = ["cssrss.exe", "cssrs.exe", "csrss.exe"]
            if procname == check:
            # if task.ImageFilename == [cssrss.exe, cssrs.exe, csrss.exe]:
                # looks suspicious
                response = "Possible impersonation attempt - CSRSS" 
           
            # Check services.exe is running from system32
            check = "services.exe"
            if procname.lower() == check:
                path = "system32\services.exe"
                if path in imgpath.lower():
                    # valid path
                    holder = "valid"
                else:
                    # invalid path
                    response = "Services.exe running from unusual location"
    
            # Check for SVCHost impersonation
            check = ["scvhost.exe","svch0st.exe","sscvhost.exe","svcchost.exe","scvh0st.exe","svchozt.exe","svchot.exe","scvhot.exe"]
            if procname.lower() == check:
                # possible impersonation
                response = "Posible impersonation of SERVICES.EXE"
                
            # Check for DLLHOST impersonation
            check = ["dllh0st.exe","dllhot.exe","d1lhost.exe","dl1host.exe","d11host.exe","d11h0st.exe"]
            if procname.lower() == check:
                # possible impersonation
                response = "Posible impersonation of DLLHOST.EXE"

            # Check for multiple lsass, eg Stuxnet :-)
            check = "lsass.exe"
            if procname == check:
                lsasscount = lsasscount+1
                # Check number of instances
                if lsasscount > 1:
                    # multiple csrss found
                    response = "Multiple instances of LSASS found"

            # Check lsass is running from system32
            if procname == check:
                path = str("\system32\lsass.exe")
                if path in imgpath.lower():
                    # valid path
                    holder = "valid"
                else:
                    # invalid path
                    response = "lsass.exe running from unusual location"

            # Check for oddly short file length executables - eg. a.exe
            #
            exename, extension = procname.split('.') # split off the first portion
            if len(exename) < 3:
                response = "Unusually short filename"
                
            # Check the extension
            if extension != "exe":
                if procname == ["System","system"]:
                    # Not suspcious
                    holder = "Valid"          
                else: 
                    # possibly suspicious
                    response = "Possibly suspicious extension"
                    
            # output in "Unified Output format"
            yield (0, [
                      int(pid),
                      str(procname),
                      str(response),
                      ])



    def unified_output(self,data):
        tree = [
                ("PID",int),
                ("Filename",str),
                ("Triage Response",str),
               ]

        return TreeGrid(tree, self.generator(data))
