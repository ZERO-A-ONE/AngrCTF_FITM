import angr
import sys
import claripy
def Go():
    path_to_binary = "./15_angr_arbitrary_read" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 'A', char <= 'Z')
            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1)
            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_puts(state):
        puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        if state.se.symbolic(puts_parameter):
            good_job_string_address = 0x594e4257
            is_vulnerable_expression = puts_parameter == good_job_string_address

            copied_state = state.copy()
            copied_state.add_constraints(is_vulnerable_expression)

            if copied_state.satisfiable():
                state.add_constraints(is_vulnerable_expression)
                return True
            else:
                return False
        else:
            return False
    
    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        puts_address = 0x8048370
        if state.addr == puts_address:
            return check_puts(state)
        else:
            return False
    
    simulation.explore(find=is_successful)

    if simulation.found:
        solution_state = simulation.found[0]
        (scanf0, scanf1) = solution_state.globals['solutions']
        solution0 = (solution_state.solver.eval(scanf0))
        solution1 = (solution_state.solver.eval(scanf1,cast_to=bytes))
        print("[+] Success! Solution is: {0} {1}".format(solution0, solution1))
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()