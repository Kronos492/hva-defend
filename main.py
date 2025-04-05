import argparse
import subprocess
import os


def stageEnvironment(args):
    if not os.path.isfile(args.file[0]):
        return "[Error] File doesn't exist."

    if not os.path.exists(args.output[0]):
        os.makedirs(args.output[0], exist_ok=True)

    pidList = [int(pid) for pid in args.pid[0].split(',')]

    return pidList


def dumpFiles(args):
    pidList = [int(pid) for pid in args.pid[0].split(',')]
    realPath=os.getcwd()+'/'+args.output[0]

    for pid in pidList:
        pid = str(pid)
        #print(args.binary[0]+' -f '+args.file[0]+' -o '+args.output[0]+'PID'+pid+'-filedump/'+' windows.dumpfiles.DumpFiles --pid '+pid)
        os.system(args.binary[0] + ' -f ' + args.file[0] + ' -o ' + realPath + 'PID' + pid + '-filedump/' + ' windows.dumpfiles.DumpFiles --pid ' + pid)

        extractStringData(realPath+'PID'+pid+'-filedump/')




def extractStringData(path):
    stringDirectory = path+'stringsOutput/'

    if not os.path.exists(stringDirectory):
        output_dir = os.path.join(path, 'stringsOutput')
        os.makedirs(output_dir, exist_ok=True)

    for file in os.listdir(path):
        filename = os.fsdecode(file)
        if filename.endswith('.dat'):
            with open(path + 'stringsOutput/strings', 'w') as f:
                subprocess.run(['strings', '-a', '-el', path+filename], stdout=f, universal_newlines=True)



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

    status = stageEnvironment(args)
    if status:
        quit(status)

    dumpFiles(args)


if __name__ == "__main__":
    main()

