import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Redirect stdout to file
import io
output = io.StringIO()
old_stdout = sys.stdout
sys.stdout = output

# Run benchmark
exec(open('benchmark_blockchain.py').read())

sys.stdout = old_stdout

# Write to UTF-8 file
with open('benchmark_output.txt', 'w', encoding='utf-8') as f:
    f.write(output.getvalue())

print("Benchmark output saved to benchmark_output.txt")
print("Lines:", len(output.getvalue().splitlines()))
