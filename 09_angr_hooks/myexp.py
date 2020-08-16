import angr
import sys
import claripy
def Go():
    path_to_binary = "./09_angr_hooks" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    check_equals_called_address = 0x80486B3
    instruction_to_skip_length = 5

    @project.hook(check_equals_called_address, length=instruction_to_skip_length)
    def skip_check_equals_(state):
        user_input_buffer_address = 0x804A054 
        user_input_buffer_length = 16

        user_input_string = state.memory.load(
            user_input_buffer_address,
            user_input_buffer_length
        )

        check_against_string = 'XKSPZSJKJYQCQXZV'

        register_size_bit = 32
        state.regs.eax = claripy.If(
            user_input_string == check_against_string, 
            claripy.BVV(1, register_size_bit), 
            claripy.BVV(0, register_size_bit)
        )

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
            solution = solution_state.posix.dumps(0)
            print("[+] Success! Solution is: {0}".format(solution.decode('utf-8')))
            #print(solution0)
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()