"""Cloud preparation entry point. No real credential input is implemented."""
import sys
from core import Result,dry_run

def dispatch(argv):
    if argv in ([],['--dry-run']):return dry_run()
    # Fail closed until an approved private handoff and live gate exist.
    if argv==['--live']:return Result('live','setup_failed')
    return Result('dry-run','invalid_arguments')

if __name__=='__main__':
    try:result=dispatch(sys.argv[1:])
    except BaseException:result=Result('dry-run','setup_failed')
    print(result.safe_json())
