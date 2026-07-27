from datetime import datetime


class Report:

    def generate(self, process, result):

        print("=" * 50)
        print("KEYLOGGER DETECTION REPORT")
        print("=" * 50)

        print(f"Date : {datetime.now()}")

        print(f"Process : {process['name']}")

        print(f"PID : {process['pid']}")

        print(f"Path : {process['path']}")

        print(f"Risk : {result['level']}")

        print(f"Score : {result['score']}")

        print("\nReasons:")

        for reason in result["reasons"]:
            print(f" - {reason}")

        print("=" * 50)
