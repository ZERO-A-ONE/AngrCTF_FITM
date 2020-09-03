import angr
import claripy
import sys

def Go():
    path_to_binary = "./17_angr_arbitrary_jump" 
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state() 
     
    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, input_buffer_address):
            input_buffer = claripy.BVS(
                'input_buffer', 64 * 8)  
            for char in input_buffer.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            self.state.memory.store(
                input_buffer_address, input_buffer, endness=project.arch.memory_endness)
            self.state.globals['solution'] = input_buffer

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    simulation = project.factory.simgr(
        initial_state, 
        save_unconstrained=True,
        stashes={
        'active' : [initial_state],
        'unconstrained' : [],
        'found' : [],
        'not_needed' : []
        }
    )

    def check_vulnerable(state):
        return state.solver.symbolic(state.regs.eip)

    def has_found_solution():
        return simulation.found

    def has_unconstrained_to_check():
        return simulation.unconstrained

    def has_active():
        return simulation.active

    while (has_active() or has_unconstrained_to_check()) and (not has_found_solution()):
        for unconstrained_state in simulation.unconstrained:
            def should_move(s):
                return s is unconstrained_state
            simulation.move('unconstrained', 'found', filter_func=should_move)
        simulation.step()

    if simulation.found:
        solution_state = simulation.found[0]
        solution_state.add_constraints(solution_state.regs.eip == 0x4d4c4749)
        solution = solution_state.solver.eval(
        solution_state.globals['solution'], cast_to=bytes)
        print(solution[::-1])
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    Go()
