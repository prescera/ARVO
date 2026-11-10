import argparse
import json
import sys
from pathlib import Path
from .reproducer import verify
from .utils import *
from .Locator import report
from .utils_log import *

def cli_reproduce(localId, save_img=False):
    # save_img: commit vul/fix images and `docker save` them into DOCKER_PUSH_QUEUE
    res = verify(localId, save_img)
    if res:
        out = OSS_IMG / f"{localId}"
        print(f"[+] Successfully reproduced {localId=}, see: {out}")
        return out
    else:
        print("[-] Failed to Reproduce")
        return False

def cli_report(localId):
    res = report(localId,False)
    print(res)
def cli_list(pname):
    res = listProject(pname)
    if not res:
        WARN(f"Not found, check the provided project name {pname=}")
    else:
        print(res)
def cli_check_localId(localId,verbose=False):
    reproduciable = True if localId in getDone() else False
    patch_located = True if localId in getReports() else False
    pname = getPname(localId)
    INFO(f"{pname=} {localId=}")
    if reproduciable:
        SUCCESS("Reproduced: \tTrue")
    else:
        WARN("Reproduced: \tFalse")
    if patch_located:
        SUCCESS("Patch Located: \tTrue")
    else:
        WARN("Patch Located: \tFalse")
    if verbose and (not reproduciable or not patch_located):
        INFO("Reasons:")
        possible_image_err   = ARVO / "CrashLog" / f"{localId}_Image.log"
        possible_compile_err = ARVO / "CrashLog" / f"{localId}_Compile.log"
        log_file = ARVO / "Log" / "_Event.log"
        crash_file = ARVO / "_CrashLOGs"
        if possible_image_err.exists():
            os.system(f"tail -n 100 {possible_image_err}")
        if possible_compile_err.exists():
            os.system(f"tail -n 100 {possible_compile_err}")
        INFO("[Event Log]")
        os.system(f"grep -r {localId} {log_file}")
        INFO("[Crash Log]")
        os.system(f"grep -r {localId} {crash_file}")
        
def cli_check(localId_project):
    if localId_project.isdigit():
        localId = int(localId_project)
        cli_check_localId(localId,True)
    else:
        pname = localId_project
        for x in listProject(pname):
            cli_check_localId(x)
    
def cli_show(localId):
    res = getReport(localId)
    if not res:
        WARN(f"No Report Found for {localId=}")
    else:
        print(json.dumps(res,indent=4))
def cli_summary():
    pass
def cli_locate(localId, image_prefix, out):
    from .Locator import locate_record
    rec = locate_record(localId, image_prefix)
    Path(out).write_text(json.dumps(rec, indent=2))
    print(f"[+] {localId}: patch_located={rec['patch_located']} -> {out}")
def cli_build_db(record_dir):
    from .Locator import build_db
    files = sorted(Path(record_dir).glob("*.json"))
    n = build_db(files)
    print(f"[+] Inserted {n}/{len(files)} records into {ARVO / 'arvo.db'}")
def cli_collect(since, until):
    from datetime import date
    from .utils_meta import getMeta, metaFilter
    getMeta(date.fromisoformat(since), date.fromisoformat(until) if until else None)
    metaFilter()
def main():
    parser = argparse.ArgumentParser(prog="arvo", description="ARVO CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # reproduce
    p_reproduce = subparsers.add_parser("reproduce", help="Reproduce a bug")
    p_reproduce.add_argument("localId", type=int)
    p_reproduce.add_argument("--save-img", action="store_true", help="Save vul/fix images to DOCKER_PUSH_QUEUE")

    # report
    p_report = subparsers.add_parser("report", help="Generate a report")
    p_report.add_argument("localId", type=int)

    # list
    p_list = subparsers.add_parser("list", help="List the localIds belong to a specific project in meta")
    p_list.add_argument("pname", type=str)

    # check status
    p_check = subparsers.add_parser("check", help="Check the reproducing status")
    p_check.add_argument("localId_project", type=str)

    # show report
    p_show = subparsers.add_parser("show", help="Print the report")
    p_show.add_argument("localId", type=int)

    # summary
    p_summary = subparsers.add_parser("summary", help="Print the summary of current reproducing process")

    # collect
    p_collect = subparsers.add_parser("collect", help="Fetch metadata and srcmaps for OSS-Fuzz issues created in [since, until)")
    p_collect.add_argument("--since", required=True, help="YYYY-MM-DD (inclusive)")
    p_collect.add_argument("--until", default=None, help="YYYY-MM-DD (exclusive, default: end of this year)")

    # locate (second pass over reproduced issues: fix commit + crash output -> one arvo.db record)
    p_locate = subparsers.add_parser("locate", help="Locate the fix commit of a reproduced issue; write an arvo.db record as JSON")
    p_locate.add_argument("localId", type=int)
    p_locate.add_argument("--image-prefix", required=True, help="Registry path holding <id>-vul/<id>-fix images")
    p_locate.add_argument("--out", required=True, help="Output JSON file")

    # build-db
    p_build_db = subparsers.add_parser("build-db", help="Insert `arvo locate` JSON records from a directory into arvo.db")
    p_build_db.add_argument("record_dir", type=str)

    args = parser.parse_args()

    if args.command == "reproduce":
        cli_reproduce(args.localId, args.save_img)
    elif args.command == "report":
        cli_report(args.localId)
    elif args.command == "list":
        cli_list(args.pname)
    elif args.command == "check":
        cli_check(args.localId_project)
    elif args.command == "show":
        cli_show(args.localId)
    elif args.command == 'summary':
        cli_summary()
    elif args.command == 'collect':
        cli_collect(args.since, args.until)
    elif args.command == 'locate':
        cli_locate(args.localId, args.image_prefix, args.out)
    elif args.command == 'build-db':
        cli_build_db(args.record_dir)

if __name__ == "__main__":
    main()
