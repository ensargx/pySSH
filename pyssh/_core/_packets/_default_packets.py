from pyssh._core._version import __version__
pySSHbanner = b"SSH-2.0-pySSH_" + __version__.encode("utf-8") + b" byEnsarGok" + b"\r\n"


def _get_pyssh_banner():
    return pySSHbanner