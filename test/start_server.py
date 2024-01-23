from pyssh import pySSH

app = pySSH(
    hostkey_path = '/home/ensargok/keys/'
)

app.run()