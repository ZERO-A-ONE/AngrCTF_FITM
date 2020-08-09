import angr
import sys
import claripy
def Go():
    path_to_binary = "./06_angr_symbolic_dynamic_memory" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address = 0x8048699
    initial_state = project.factory.blank_state(addr=start_address)

    passwd_size_in_bits = 64
    passwd0 = claripy.BVS('passwd0', passwd_size_in_bits)
    passwd1 = claripy.BVS('passwd1', passwd_size_in_bits)

    fake_heap_address0 = 0xffffc93c
    pointer_to_malloc_memory_address0 = 0xabcc8a4
    fake_heap_address1 = 0xffffc94c
    pointer_to_malloc_memory_address1 = 0xabcc8ac
    initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
    initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

    initial_state.memory.store(fake_heap_address0, password0)  
    initial_state.memory.store(fake_heap_address1, password1)

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
            solution0 = solution_state.solver.eval(passwd0, cast_to=bytes)
            solution1 = solution_state.solver.eval(passwd1, cast_to=bytes)
            print("[+] Success! Solution is: {0} {1}".format(solution0.decode('utf-8'), solution1.decode('utf-8')))
            #print(solution0, solution1)
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()