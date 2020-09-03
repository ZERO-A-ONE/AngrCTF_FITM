import angr
import claripy
import sys

def Go():
    path_to_binary = "./11_angr_sim_scanf" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 32)

            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

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
            stored_solutions = solution_state.globals['solutions']
            scanf0_solution = solution_state.solver.eval(stored_solutions[0])
            scanf1_solution = solution_state.solver.eval(stored_solutions[1])
            print("[+] Success! Solution is: {0} {1}".format(scanf0_solution,scanf1_solution))
            #print(scanf0_solution, scanf1_solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()