import angr
import sys
import claripy
def Go():
    path_to_binary = "./05_angr_symbolic_memory" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x8048601
    initial_state = project.factory.blank_state(addr=start_address)
 
    passwd_size_in_bits = 64
    passwd0 = claripy.BVS('passwd0', passwd_size_in_bits)
    passwd1 = claripy.BVS('passwd1', passwd_size_in_bits)
    passwd2 = claripy.BVS('passwd2', passwd_size_in_bits)
    passwd3 = claripy.BVS('passwd3', passwd_size_in_bits)

    passwd0_address = 0xA1BA1C0
    #passwd1_address = 0xA1BA1C8
    #passwd2_address = 0xA1BA1D0
    #passwd3_address = 0xA1BA1D8
    initial_state.memory.store(passwd0_address, passwd0)
    initial_state.memory.store(passwd0_address + 0x8,  passwd1)
    initial_state.memory.store(passwd0_address + 0x10, passwd2)
    initial_state.memory.store(passwd0_address + 0x18, passwd3)

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
            solution0 = solution_state.solver.eval(passwd0,cast_to=bytes)
            solution1 = solution_state.solver.eval(passwd1,cast_to=bytes)
            solution2 = solution_state.solver.eval(passwd2,cast_to=bytes)
            solution3 = solution_state.solver.eval(passwd3,cast_to=bytes)
            solution = solution0 + b" " + solution1 + b" " + solution2 + b" " + solution3
            print("[+] Success! Solution is: {}".format(solution.decode("utf-8")))
            #print(solution0, solution1, solution2, solution3)
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()