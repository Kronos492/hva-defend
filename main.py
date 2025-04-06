import argparse
import subprocess
import os


def stageEnvironment(args):
    dumpTypes = ['filedumps','strings','dll','strings-vs']
    pidList = [int(pid) for pid in args.pid[0].split(',')]

    if not args.output[0].endswith('/'):
        args.output[0] += '/'

    realPath = os.getcwd() + '/' + args.output[0]

    if not os.path.isfile(args.file[0]):
        return

    if not os.path.exists(args.output[0]):
        os.makedirs(args.output[0], exist_ok=True)

    for dumpType in dumpTypes:
        dumpDir = f'{realPath}{dumpType}/'
        os.makedirs(f'{dumpDir}', exist_ok=True)

        if dumpType != 'strings':
            for pid in pidList:
                pid = str(pid)
                os.makedirs(f'{dumpDir}PID-{pid}/', exist_ok=True)

    return pidList, realPath


def iteratePIDs(args, pidList, realPath):
    pidCount = len(pidList)

    for i, pid in enumerate(pidList, start=1):
        print()
        print(f'[Info]: Processing {i}/{pidCount}')
        print()

        fileDump(args, pid, realPath)

        if args.strings:
            if args.volatilitystrings:
                extractStringDataVolatility(args, pid, realPath)
            else:
                extractStringData(pid, realPath)

        if args.dll:
            dllList(args, pid, realPath)


def fileDump(args, pid, realPath):
    pid = str(pid)
    os.system(f'{args.binary[0]} -f {args.file[0]} -o {realPath}filedumps/PID-{pid} windows.dumpfiles.DumpFiles --pid {pid}')


def extractStringData(pid, realPath):
    dumpDir = f'{realPath}filedumps/PID-{pid}/'

    for file in os.listdir(dumpDir):
        filename = os.fsdecode(file)
        if filename.endswith('.dat'):
            with open(f'{realPath}strings/PID-{pid}', 'w') as f:
                subprocess.run(['strings', '-a', '-el', dumpDir+filename], stdout=f, universal_newlines=True)


def extractStringDataVolatility(args, pid, realPath):
    dumpDir = f'{realPath}filedumps/PID-{pid}/'

    for file in os.listdir(dumpDir):
        filename = os.fsdecode(file)
        if filename.endswith('.dat'):
            dumpFile = f'{dumpDir}{filename}'
            os.system(f'{args.binary[0]} -f {args.file[0]} -o {realPath}strings-vs/PID-{pid} windows.strings --strings-file {dumpFile}')


def dllList(args, pid, realPath):
    os.system(f'{args.binary[0]} -f {args.file[0]} -o {realPath}dll/PID-{pid} windows.dlllist.DllList --pid {pid}')


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
        help='Input one or multiple Process ID\'s that you want to analyse (standard filedump). Delimit with \',\' like so: 145,45,12.'
    )
    parser.add_argument(
        '-s', '--strings', type=bool, nargs='?', const=True, default=False,
        help='Extract strings data from all PID\s.'
    )
    parser.add_argument(
        '-d', '--dll', type=bool, nargs='?', const=True, default=False,
        help='Do a DLL analysis on all PID\'s.'
    )
    parser.add_argument(
        '-vs', '--volatilitystrings', type=bool, nargs='?', const=True, default=False,
        help='Use volatility\'s more comprehensive strings module instead of the strings binary.'
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

    iteratePIDs(args, pidList, realPath)


if __name__ == "__main__":
    main()

