#include <fstream>
#include <iostream>

int main(int argc, char* argv[]) {
  // Check if enough arguments were passed
  if (argc < 3) {
    std::cerr << "Usage: " << argv[0] << " <input_file> <output_file>" << std::endl;
    return 1;
  }

  // Open the input file
  std::ifstream input_file(argv[1], std::ios::binary);
  if (!input_file) {
    std::cerr << "Error: Could not open input file " << argv[1] << std::endl;
    return 1;
  }

  // Open the output file
  std::ofstream output_file(argv[2], std::ios::binary);
  if (!output_file) {
    std::cerr << "Error: Could not open output file " << argv[2] << std::endl;
    return 1;
  }

  // Encrypt the file
  char key = 'K';  // Key used for XOR encryption
  char buffer;
  while (input_file.read(&buffer, 1)) {
    buffer ^= key;
    output_file.write(&buffer, 1);
  }

  // Close the input and output files
  input_file.close();
  output_file.close();

  return 0;
}