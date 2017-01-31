from lib.cleaner import deduplicate


class FileWriter:
    def __init__(self, fileName, content):
        try:
            self.filename = fileName
            self.content = deduplicate(content).result
            self.write(content)
        except IOError:
            print("Unable to save {} file due to IOError".format(self.filename))

    def write(self):
        with open(self.fileName) as cf:
            for line in content:
                cf.write(line)

