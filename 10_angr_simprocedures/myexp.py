import angr
import claripy
import sys

def Go():
    path_to_binary = "./10_angr_simprocedures" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class ReplacementCheckEquals(angr.SimProcedure):
        def run(self, to_check, length):
            user_input_buffer_address = to_check
            user_input_buffer_length = length
            user_input_string = self.state.memory.load(
                user_input_buffer_address,
                user_input_buffer_length
            )
            check_against_string = 'ORSDDWXHZURJRBDH'
            return claripy.If(
                user_input_string == check_against_string, 
                claripy.BVV(1, 32), 
                claripy.BVV(0, 32)
            )
    
    check_equals_symbol = 'check_equals_ORSDDWXHZURJRBDH'
    project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

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