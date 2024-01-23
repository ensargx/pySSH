from pyssh import pySSH

app = pySSH(
    hostkey_path="~/keys/",
)

app.run()