import angr
import sys
import claripy
def Go():
    path_to_binary = "./07_angr_symbolic_file" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    start_address =  0x80488EA
    initial_state = project.factory.blank_state(addr=start_address)

    filename = 'OJKSQYDP.txt'
    symbolic_file_size_bytes = 64
    passwd0 = claripy.BVS('password', symbolic_file_size_bytes * 8)
    passwd_file = angr.storage.SimFile(filename, content=passwd0, size=symbolic_file_size_bytes)

    initial_state.fs.insert(filename, passwd_file)

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
            print("[+] Success! Solution is: {0}".format(solution0.decode('utf-8')))
            #print(solution0)
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()