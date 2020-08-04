import angr
import sys
def Go():
    path_to_binary = "./01_angr_avoid" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    avoid_me_address =   0x080485A8
    maybe_good_address = 0x080485E0

    simulation.explore(find=maybe_good_address, avoid=avoid_me_address)
  
    if simulation.found:
        solution_state = simulation.found[0]
        solution = solution_state.posix.dumps(sys.stdin.fileno())
        print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
    else:
        raise Exception('Could not find the solution')
if __name__ == "__main__":
    Go()