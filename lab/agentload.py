#!/usr/bin/env python3
"""A fixed-duty CPU hog for `lab paired --split --agent-load`.

  agentload.py start CPU DUTY_PERCENT STATEFILE   pin to CPU, busy DUTY percent of every 10 ms
  agentload.py stop STATEFILE                     stop it and print its share of the CPU
  agentload.py kill STATEFILE                     SIGKILL it and remove the state files; never fails

`start` returns once the hog runs. `stop` prints one line:
  AGENTLOAD cpu=N duty=D wall_s=W cpu_s=C share=S
where share is the CPU time the hog used over the wall time it ran. A share below DUTY/100 means
something else wanted the CPU as well (the agent's own threads, for example) and the hog was descheduled.
"""
import os
import signal
import sys
import time

PERIOD = 0.010


def hog(cpu, duty, state):
    os.sched_setaffinity(0, {cpu})
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    t0 = time.monotonic()
    c0 = time.process_time()
    busy = PERIOD * duty / 100.0
    while not stop:
        s = time.monotonic()
        if busy > 0:
            while time.monotonic() - s < busy and not stop:
                pass
        rest = PERIOD - (time.monotonic() - s)
        if rest > 0 and not stop:
            time.sleep(rest)
    wall = time.monotonic() - t0
    cpu_s = time.process_time() - c0
    with open(state + ".result", "w") as f:
        f.write(f"AGENTLOAD cpu={cpu} duty={duty} wall_s={wall:.3f} cpu_s={cpu_s:.3f} share={cpu_s / wall if wall else 0:.3f}\n")


def alive(state):
    try:
        os.kill(int(open(state).read()), 0)
        return True
    except (OSError, ValueError):
        return False


def kill(state):
    """SIGKILL the hog if it runs and remove the state files. Never raises."""
    try:
        os.kill(int(open(state).read()), signal.SIGKILL)
    except (OSError, ValueError):
        pass
    for p in (state, state + ".result"):
        try:
            os.unlink(p)
        except OSError:
            pass


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "start":
        cpu, duty, state = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
        if not 0 <= duty <= 100:
            sys.exit("agentload: DUTY_PERCENT wants 0 to 100")
        if cpu not in os.sched_getaffinity(0):
            sys.exit(f"agentload: CPU {cpu} is not available here")
        if os.path.exists(state):
            if alive(state):
                sys.exit(f"agentload: {state} exists and its hog is running")
            kill(state)  # a stale state of a hog that is gone
        pid = os.fork()
        if pid:
            with open(state, "w") as f:
                f.write(f"{pid}\n")
            time.sleep(0.2)
            if os.waitpid(pid, os.WNOHANG) != (0, 0):
                kill(state)
                sys.exit("agentload: the hog did not start")
            return
        os.setsid()
        for fd in (0, 1, 2):
            os.close(fd)
        os.open(os.devnull, os.O_RDWR)
        os.dup2(0, 1)
        os.dup2(0, 2)
        hog(cpu, duty, state)
        os._exit(0)
    elif len(sys.argv) == 3 and sys.argv[1] == "stop":
        state = sys.argv[2]
        try:
            pid = int(open(state).read())
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(100):
                if os.path.exists(state + ".result"):
                    break
                time.sleep(0.05)
            else:
                sys.exit("agentload: the hog left no result")
            sys.stdout.write(open(state + ".result").read())
        except (OSError, ValueError) as e:
            sys.exit(f"agentload: cannot stop the hog: {e}")
        finally:
            kill(state)
    elif len(sys.argv) == 3 and sys.argv[1] == "kill":
        kill(sys.argv[2])
    else:
        sys.exit(__doc__)


main()
