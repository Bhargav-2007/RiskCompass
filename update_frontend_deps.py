import json
import subprocess
import sys

# Get the current package.json
with open('package.json', 'r') as f:
    package = json.load(f)

# Function to get dependencies from pnpm list
def get_pnpm_list(args):
    try:
        result = subprocess.run(['pnpm', 'list', '--json'] + args, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            print(f"Error running pnpm list {' '.join(args)}: {result.stderr}")
            return {}
        return json.loads(result.stdout)
    except Exception as e:
        print(f"Exception running pnpm list: {e}")
        return {}

# Get production dependencies
prod_deps = get_pnpm_list(['--prod', '--depth=0'])
# Get dev dependencies
dev_deps = get_pnpm_list(['--dev', '--depth=0'])

# Update package.json
# The output of pnpm list is a dictionary with the package name as key and an object containing version.
for dep in list(package.get('dependencies', {}).keys()):
    if dep in prod_deps:
        package['dependencies'][dep] = prod_deps[dep]['version']
    else:
        print(f"Warning: {dep} not found in production dependencies list")

for dep in list(package.get('devDependencies', {}).keys()):
    if dep in dev_deps:
        package['devDependencies'][dep] = dev_deps[dep]['version']
    else:
        print(f"Warning: {dep} not found in dev dependencies list")

# Write back
with open('package.json', 'w') as f:
    json.dump(package, f, indent=2)

print("Updated package.json with locked versions")