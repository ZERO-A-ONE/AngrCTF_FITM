import angr
import claripy
import sys

def Go():
    path_to_binary = "./13_angr_static_binary" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
    project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
    project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
    project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    simulation = project.factory.simgr(initial_state, veritesting=True)

    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        if b'Good Job.\n' in stdout_output:
            return True
        else: 
            return False

    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        if b'Try again.\n' in  stdout_output:
            return True
        else: 
            return False

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            solution = solution_state.posix.dumps(0)
            print("[+] Success! Solution is: {0}".format(solution))
            #print(scanf0_solution, scanf1_solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()