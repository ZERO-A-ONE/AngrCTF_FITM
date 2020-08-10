import angr
import sys
import claripy
def Go():
    path_to_binary = "./08_angr_constraints" 
    project = angr.Project(path_to_binary, auto_load_libs=False)

    start_address = 0x8048625
    buff_addr = 0x0804A050
    address_to_check_constraint = 0x08048565

    initial_state = project.factory.blank_state(addr=start_address)
   
    char_size_in_bits = 8
    passwd_len = 16
    passwd0 = claripy.BVS('passwd0', char_size_in_bits*passwd_len)
    initial_state.memory.store(buff_addr, passwd0)

    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=address_to_check_constraint)

    if simulation.found:
        solution_state = simulation.found[0]
        constrained_parameter_address = buff_addr
        constrained_parameter_size_bytes = 16
        constrained_parameter_bitvector = solution_state.memory.load(
        constrained_parameter_address,
        constrained_parameter_size_bytes
    )
        constrained_parameter_desired_value = 'AUPDNNPROEZRJWKB'
        solution_state.solver.add(constrained_parameter_bitvector == constrained_parameter_desired_value)
        solution0 = solution_state.solver.eval(passwd0,cast_to=bytes)       
        print("[+] Success! Solution is: {0}".format(solution0))
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()