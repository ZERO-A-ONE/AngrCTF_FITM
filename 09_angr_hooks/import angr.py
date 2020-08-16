import angr
import claripy
import sys

def main(argv):
    bin_path = argv[1]
    project = angr.Project(bin_path)

    initial_state = project.factory.entry_state()

    check_equals_called_address = 0x80486B3

    instruction_to_skip_length = 5

    @project.hook(check_equals_called_address, length=instruction_to_skip_length)
    def skip_check_equals_(state):
        user_input_buff_address = 0x804a054
        user_input_buff_length = 16
        user_input_string = state.memory.load(
            user_input_buff_address,
            user_input_buff_length
        )

        check_against_string = "XKSPZSJKJYQCQXZV"

        state.regs.eax = claripy.If (
            user_input_string == check_against_string,
            claripy.BVV(1, 32),
            claripy.BVV(0, 32)
        )

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        return b"Good Job." in stdout_output

    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        return b"Try again." in stdout_output

    simulation.explore(find = is_successful, avoid = should_abort)

    if simulation.found:
        print(simulation.found[0].posix.dumps(0))
    else:
        raise(Exception("Could not find the solution"))

if __name__ == "__main__":
    main(sys.argv)