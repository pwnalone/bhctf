#!/usr/bin/python3

from common import *

ACTIONS = { 'start' : RT_CTL_START, 'stop' : RT_CTL_STOP, 'status' : RT_CTL_STATUS }

if len(sys.argv) < 3:
    print('Usage: python rtctl.py start|stop|status <RID>')
    print('')
    print('  Control the service with the given <RID>.')
    print('')
    print('E.g.   python rtctl.py start 13 37')
    sys.exit(0)

action = ACTIONS.get(sys.argv[1], None)
rid    = int(''.join(sys.argv[2:]), 16)
if not action:
    print(f'Invalid action -- {sys.argv[1]!r}')
    sys.exit(1)
else:
    data = rtctl(socket(), rid, action)
    if len(data) > 0:
        print(data.decode())
