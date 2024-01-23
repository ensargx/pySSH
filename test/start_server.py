import pyssh

def main():
    app = pyssh.pySSH(
        hostkey_path="~/keys/"
    )

    app.run()


if __name__ == '__main__':
    main()
