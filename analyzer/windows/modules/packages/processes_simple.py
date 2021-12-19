from __future__ import absolute_import
import os
import time

from lib.common.abstracts import Package


class PROCESSES_simply(Package):

    """Word analysis package."""

    PATHS = [
        ("ProgramFiles", "Microsoft Office", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office*", "root", "Office*", "WINWORD.EXE"),
        ("ProgramFiles", "Microsoft Office", "WORDVIEW.EXE"),
    ]

    def start(self, path):

        for i in range(20):
            # calc
            calc = os.path.join("C:\\windows", "system32", "calc.exe")
            # cl = Process()
            self.execute(calc, "", path)
        # cl.close()
        """
            iexplore = os.path.join("C:\\Program Files", "Internet Explorer", "iexplore.exe")
            #ie = Process()
            self.execute(iexplore, "", path)
            #ie.close()

            #firefox
            firefox = os.path.join("C:\\Program Files", "Mozilla Firefox", "firefox.exe")
            #ff = Process()
            self.execute(firefox, "", path)
            #ff.close()

            #winrar
            #winrar = os.path.join("C:\\Program Files", "WinRAR", "WinRAR.exe")
            #wr = Process()
            #self.execute(winrar, "", path)
            #wr.close()

            #media player
            mc = os.path.join("C:\\Program Files", "Windows Media Player", "wmplayer.exe")
            #mc_p = Process()
            self.execute(mc, "/prefetch:1", path)
            #mc_p.close()

            #adobe pdf reader
            pdf = os.path.join("C:\\Program Files", "Adobe", "Reader 11.0", "Reader", "AcroRd32.exe")
            #pdf_p = Process()
            self.execute(mc, "", path)
            #pdf_p.close()

            #snipping tool
            #snt = os.path.join("C:\\windows", "system32", "Snipping Tool.exe")
            #snt_p = Process()
            #self.execute(snt, "", path)
            #snt_p.close()

            #backup and restore tool
            bnr = os.path.join("C:\\windows", "system32", "control.exe")
            #bnr_p = Process()
            self.execute(bnr, "/name Microsoft.BackupAndRestore", path)
            #bnr_p.close()

            #on screen keyboard
            konscr = os.path.join("C:\\windows", "system32", "osk.exe")
            #konscr_p = Process()
            self.execute(konscr, "", path)
            #konscr_p.close()

            #sync center
            mobs = os.path.join("C:\\windows", "system32", "mobsync.exe")
            #mobs_p = Process()
            self.execute(mobs, "", path)
            #mobs_p.close()

            #rdp
            rdp = os.path.join("C:\\windows", "system32", "mstsc.exe")
            #rdp_p = Process()
            self.execute(rdp, "", path)
            #rdp_p.close()

            #char map
            chrm = os.path.join("C:\\windows", "system32", "charmap.exe")
            #chrm_p = Process()
            self.execute(chrm, "", path)
            #chrm_p.close()

            #media center
            #mc = os.path.join("C:\\windows", "system32", "ehshell.exe")
            #mc_p = Process()
            #self.execute(mc, "", path)
            #mc_p.close()
            #xps viewer
            xps = os.path.join("C:\\windows", "system32", "xpschvw.exe")
            #xps_v = Process()
            self.execute(xps, "", path)
            #xps_v.close()
            #notepad
            #notepad = os.path.join("C:\\windows", "system32", "notepad32.exe")
            #np = Process()
            #self.execute(notepad, "", path)
            #np.close()

            #calc
            calc = os.path.join("C:\\windows", "system32", "calc.exe")
            #cl = Process()
            self.execute(calc, "", path)
            #cl.close()

            #paint
            paint = os.path.join("C:\\windows", "system32", "mspaint.exe")
            #pnt = Process()
            self.execute(paint, "", path)
            #pnt.close()
            """
        time.sleep(5)
        word = self.get_path_glob("Microsoft Office Word")
        return self.execute(word, f'"{path}" /q', path)
