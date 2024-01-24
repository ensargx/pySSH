from pyssh import pySSH
import os

hostkey_path = os.path.join(os.path.expanduser('~'), 'keys')

app = pySSH(
    hostkey_path = hostkey_path
)

print("Starting Server")
app.run()
