import angr
import sys
import claripy
def Go():
    path_to_binary = "./17_angr_arbitrary_jump" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()