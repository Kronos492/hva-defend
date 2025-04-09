import argparse
import subprocess
import os

# This function creates all the folders required to store the analysis.
def stageEnvironment(args):
    dumpTypes = []
    pidList = [int(pid) for pid in args.pid[0].split(',')]

    if not args.output[0].endswith('/'):
        args.output[0] += '/'

    realPath = os.getcwd() + '/' + args.output[0]

    if not os.path.isfile(args.file[0]):
        quit(f'[Error]: Can\'t find file: {args.file[0]}')

    if not os.path.exists(args.output[0]):
        os.makedirs(args.output[0], exist_ok=True)

    if args.filedump:
        dumpTypes.append('filedumps')

    if args.strings:
        if args.filedump:
            dumpTypes.append('stringdumps')
        else:
            quit(f'[Error]: Can\'t extract strings without -fd.')

    if args.dll:
        dumpTypes.append('dlldumps')

    if args.volatilitystrings:
        dumpTypes.append('vs-stringdumps')

    if len(dumpTypes) == 0:
        quit('[Error]: No dump types specified(-fd, -dd, -vs, -sd). Use -h for more information.')

    print('[Info]: Creating folders.')
    for dumpType in dumpTypes:
        dumpDir = f'{realPath}{dumpType}/'
        os.makedirs(f'{dumpDir}', exist_ok=True)

        if dumpType == 'filedumps' or dumpType == 'dlldumps':
            for pid in pidList:
                pid = str(pid)
                os.makedirs(f'{dumpDir}PID-{pid}/', exist_ok=True)

    return pidList, realPath


# This function iterates over the given PIDs and keeps track of the count. This function is primarily here to manage the loop and call other functions.
def iteratePIDs(args, pidList, realPath):
    pidCount = len(pidList)

    for i, pid in enumerate(pidList, start=1):
        print()
        print(f'[Info]: Processing {i}/{pidCount}.')
        print()

        if args.filedump:
            print(f'[Info]: Dumping files from PID {pid}.')
            fileDump(args, pid, realPath)

        if args.strings:
            print(f'[Info]: Extracting strings from {pid}\'s filedump.')
            extractStringData(pid, realPath)

        if args.dll:
            print(f'[Info]: Dumping {pid}\'s used dlls.')
            dllList(args, pid, realPath)

        if args.volatilitystrings:
            print(f'[Info]: Sorting {pid}\'s string text.')
            volatilityStringSort(pid, realPath)


# This function runs volatility3 and creates a filedump of a given PID.
def fileDump(args, pid, realPath):
    pid = str(pid)
    os.system(f'{args.binary[0]} -f {args.file[0]} -o {realPath}filedumps/PID-{pid} windows.dumpfiles.DumpFiles --pid {pid}')


# This function runs volatility3 and extracts strings from a filedump of a given PID.
def extractStringData(pid, realPath):
    dumpDir = f'{realPath}filedumps/PID-{pid}/'

    for file in os.listdir(dumpDir):
        filename = os.fsdecode(file)
        if filename.endswith('.dat'):
            with open(f'{realPath}stringdumps/PID-{pid}', 'w') as f:
                subprocess.run(['strings', '-a', '-el', dumpDir+filename], stdout=f, universal_newlines=True)


# This function uses the volatility strings module instead of the strings command to extract strings from a filedump of a given PID.
def extractStringDataVolatility(args, realPath):
    extractedStringFile = f'{realPath}vs-stringdumps/extractedStrings.txt'
    translatedMappedFile = f'{realPath}vs-stringdumps/mappedStrings.txt'

    print('[Warn]: This process can take a lot of RAM and might cause the system to run Out Of Memory(OOM), please monitor RAM usage.')
    os.system(f'{args.binary[0]} -f {args.file[0]}  windows.strings --strings-file {extractedStringFile} > {translatedMappedFile}')


# This function runs volatility to extract a dlllist from a given PID.
def dllList(args, pid, realPath):
    os.system(f'{args.binary[0]} -f {args.file[0]} -o {realPath}dlldumps/PID-{pid} windows.dlllist.DllList --pid {pid}')


def volatilityStringSort(pid, realPath):
    os.system(f'cat {realPath}vs-stringdumps/mappedStrings.txt | grep -A 1 "Process {pid}" > {realPath}vs-stringdumps/PID-{pid}.txt')


# Main function containing the argparse code(for arguments) and the initial calls to the other parts of the script.
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
        help='Input one or multiple Process ID\'s that you want to analyse. Delimit with \',\' like so: 145,45,12'
    )
    parser.add_argument(
        '-fd', '--filedump', type=bool, nargs='?', const=True, default=False,
        help='Extract files from the memory dump.'
    )
    parser.add_argument(
        '-sd', '--strings', type=bool, nargs='?', const=True, default=False,
        help='Extract strings from the filedump\'s .dat files.'
    )
    parser.add_argument(
        '-dd', '--dll', type=bool, nargs='?', const=True, default=False,
        help='Create a list of used DLL\'s per proces.'
    )
    parser.add_argument(
        '-vs', '--volatilitystrings', type=bool, nargs='?', const=True, default=False,
        help='Generate a list of all strings from the dump and assign the origin proces of each string.'
    )
    parser.add_argument(
        '-o', '--output', type=str, nargs=1, default=['mem-analysis/'],
        help='Set a folder to which the results will be written. default is "mem-analysis/".'
    )
    parser.add_argument(
        '-b', '--binary', type=str, nargs=1, default=['volatility3'],
        help='Name of the volatility3 Binary. Default is volatility3.'
    )
    args = parser.parse_args()

    pidList, realPath = stageEnvironment(args)

    if args.volatilitystrings:
        print('[Info]: Extracting string text from the memory dump. This may take a while..')
        extractedStringFile = f'{realPath}vs-stringdumps/extractedStrings.txt'
        os.system(f'strings -o {args.file[0]} > {extractedStringFile}')

        print('[Info]: Mapping strings to processes.')
        extractStringDataVolatility(args, realPath)

    iteratePIDs(args, pidList, realPath)


# Initial call.
if __name__ == "__main__":
    main()

