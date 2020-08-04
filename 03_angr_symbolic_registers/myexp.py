import angr
import sys
import claripy
def Go():
    path_to_binary = "./03_angr_symbolic_registers" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x08048980
    initial_state = project.factory.blank_state(addr=start_address)

    passwd_size_in_bits = 32
    passwd0 = claripy.BVS('passwd0', passwd_size_in_bits)
    passwd1 = claripy.BVS('passwd1', passwd_size_in_bits)
    passwd2 = claripy.BVS('passwd2', passwd_size_in_bits)

    initial_state.regs.eax = passwd0
    initial_state.regs.ebx = passwd1
    initial_state.regs.edx = passwd2
    
    simulation = project.factory.simgr(initial_state) 

    def is_successful(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        if b'Good Job.\n' in stdout_output:
            return True
        else: 
            return False

    def should_abort(state):
        stdout_output = state.posix.dumps(sys.stdout.fileno())
        if b'Try again.\n' in  stdout_output:
            return True
        else: 
            return False

    simulation.explore(find=is_successful, avoid=should_abort)
  
    if simulation.found:
        for i in simulation.found:
            solution_state = i
            solution0 = format(solution_state.solver.eval(passwd0), 'x')
            solution1 = format(solution_state.solver.eval(passwd1), 'x')
            solution2 = format(solution_state.solver.eval(passwd2), 'x')
            solution = solution0 + " " + solution1 + " " + solution2
            print("[+] Success! Solution is: {}".format(solution))
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()