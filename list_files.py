import re

def find_sif_files(text):
  """
  Finds filenames ending with '.sif' in a string.

  Args:
      text: The string to search within.

  Returns:
      A list of found '.sif' filenames, or an empty list if none are found.
  """
  pattern = r'\b\w+\.sif\b' # Regex to match .sif files
  matches = re.findall(pattern, text)
  return matches


# Example usage
text = "mpirun -np 1 apptainer run --bind result:/opt/result miniamr_latest.sif /opt/miniAMR/openmp/miniAMR.x --max_blocks 6000 --num_refine 4 --init_x 1 --init_y 1 --init_z 1 --npx 1 --npy 1 --npz 1 --nx 8 --ny 8 --nz 8 --num_objects 1 --object 2 0 -0.01 -0.01 -0.01 0.0 0.0 0.0 0.0 0.0 0.0 0.0009 0.0009 0.0009 --num_tsteps 200 --comm_vars 2"
found_files = find_sif_files(text)

if found_files:
    print("Found .sif files:")
    for file in found_files:
        print(file)
else:
    print("No .sif files found.")
