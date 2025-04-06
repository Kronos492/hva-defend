import argparse
import subprocess
import os


def stageEnvironment(args):
    pidList = [int(pid) for pid in args.pid[0].split(',')]

    if not args.output[0].endswith('/'):
        args.output[0] += '/'

    realPath = os.getcwd() + '/' + args.output[0]

    if not os.path.isfile(args.file[0]):
        return

    if not os.path.exists(args.output[0]):
        os.makedirs(args.output[0], exist_ok=True)

    for pid in pidList:
        pid = str(pid)
        os.makedirs(f'{realPath}filedump-PID{pid}/', exist_ok=True)

    return pidList, realPath


def dumpFiles(args, pidList, realPath):
    pidCount = len(pidList)

    for i, pid in enumerate(pidList, start=1):
        print()
        print(f'[Info]: Processing {i}/{pidCount}')
        print()
        pid = str(pid)
        os.system(f'{args.binary[0]} -f {args.file[0]} -o {realPath}filedump-PID{pid}/ windows.dumpfiles.DumpFiles --pid {pid}')

        extractStringData(realPath, pid)


def extractStringData(realPath, pid):
    dumpDir = realPath+'filedump-PID'+pid+'/'

    for file in os.listdir(dumpDir):
        filename = os.fsdecode(file)
        if filename.endswith('.dat'):
            with open(f'{realPath}strings-PID{pid}', 'w') as f:
                subprocess.run(['strings', '-a', '-el', dumpDir+filename], stdout=f, universal_newlines=True)



def main():
    parser = argparse

    # Set the argument parser and define the -f/--file and -d/--debug terminal arguments.
    parser = argparse.ArgumentParser(
        description='sum the integers at the command line')
    parser.add_argument(
        '-f', '--file', type=str, nargs=1, required=True,
        help='Specify the full path and filename of the memory sample.'
    )
    parser.add_argument(
        '-p', '--pid', type=str, nargs=1, required=True,
        help='Input one or multiple Process ID\'s that you want to analyse. Delimit with \',\' like so: 145,45,12.'
    )
    parser.add_argument(
        '-o', '--output', type=str, nargs=1, default=['mem-analysis/'],
        help='To which folder the results should be written. default is mem-analysis/.'
    )
    parser.add_argument(
        '-b', '--binary', type=str, nargs=1, default=['volatility3'],
        help='Name of the volatility3 Binary. Default is volatility3.'
    )
    args = parser.parse_args()

    pidList, realPath = stageEnvironment(args)
    if not pidList:
        quit("[Error]: Failed to create directory or stage environment.")

    dumpFiles(args, pidList, realPath)


if __name__ == "__main__":
    main()

