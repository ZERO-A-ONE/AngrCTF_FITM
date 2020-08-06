import angr
import sys
import claripy
def Go():
    path_to_binary = "./04_angr_symbolic_stack" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x8048697
    initial_state = project.factory.blank_state(addr=start_address)

    initial_state.regs.ebp = initial_state.regs.esp
 
    passwd_size_in_bits = 32
    passwd0 = claripy.BVS('passwd0', passwd_size_in_bits)
    passwd1 = claripy.BVS('passwd1', passwd_size_in_bits)

    padding_length_in_bytes = 0x8
    initial_state.regs.esp -= padding_length_in_bytes
    
    initial_state.stack_push(passwd0)  
    initial_state.stack_push(passwd1) 

    simulation = project.factory.simgr(initial_state)
    
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
            solution0 = (solution_state.solver.eval(passwd0))
            solution1 = (solution_state.solver.eval(passwd1))
            print("[+] Success! Solution is: {0} {1}".format(solution0, solution1))
            #print(solution0, solution1)
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()