"""Transform GolfMCP components into standalone FastMCP code.

This module provides utilities for transforming GolfMCP's convention-based code
into explicit FastMCP component registrations.
"""

import ast
from pathlib import Path
from typing import Any

from golf.core.parser import ParsedComponent


class ImportTransformer(ast.NodeTransformer):
    """AST transformer for rewriting imports in component files."""

    def __init__(
        self,
        original_path: Path,
        target_path: Path,
        import_map: dict[str, str],
        project_root: Path,
    ) -> None:
        """Initialize the import transformer.

        Args:
            original_path: Path to the original file
            target_path: Path to the target file
            import_map: Mapping of original module paths to generated paths
            project_root: Root path of the project
        """
        self.original_path = original_path
        self.target_path = target_path
        self.import_map = import_map
        self.project_root = project_root

    def visit_Import(self, node: ast.Import) -> Any:
        """Transform import statements."""
        return node

    def visit_ImportFrom(self, node: ast.ImportFrom) -> Any:
        """Transform import from statements."""
        if node.module is None:
            return node

        # Handle relative imports
        if node.level > 0:
            # Calculate the source module path
            source_dir = self.original_path.parent
            for _ in range(node.level - 1):
                source_dir = source_dir.parent

            if node.module:
                source_module = source_dir / node.module.replace(".", "/")
            else:
                source_module = source_dir

            # Check if this is a common module import
            source_str = str(source_module.relative_to(self.project_root))
            if source_str in self.import_map:
                # Replace with absolute import
                new_module = self.import_map[source_str]
                return ast.ImportFrom(module=new_module, names=node.names, level=0)

        return node


def transform_component(
    component: ParsedComponent,
    output_file: Path,
    project_path: Path,
    import_map: dict[str, str],
    source_file: Path = None,
) -> str:
    """Transform a GolfMCP component into a standalone FastMCP component.

    Args:
        component: Parsed component to transform
        output_file: Path to write the transformed component to
        project_path: Path to the project root
        import_map: Mapping of original module paths to generated paths
        source_file: Optional path to source file (for common.py files)

    Returns:
        Generated component code
    """
    # Read the original file
    if source_file is not None:
        file_path = source_file
    elif component is not None:
        file_path = Path(component.file_path)
    else:
        raise ValueError("Either component or source_file must be provided")

    with open(file_path) as f:
        source_code = f.read()

    # Parse the source code into an AST
    tree = ast.parse(source_code)

    # Transform imports
    transformer = ImportTransformer(file_path, output_file, import_map, project_path)
    tree = transformer.visit(tree)

    # Get all imports and docstring
    imports = []
    docstring = None

    # Find the module docstring if present
    if (
        len(tree.body) > 0
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        docstring = tree.body[0].value.value

    # Find imports
    for node in tree.body:
        if isinstance(node, ast.Import | ast.ImportFrom):
            imports.append(node)

    # Generate the transformed code
    transformed_imports = ast.unparse(ast.Module(body=imports, type_ignores=[]))

    # Build full transformed code
    transformed_code = transformed_imports + "\n\n"

    # Add docstring if present, using proper triple quotes for multi-line docstrings
    if docstring:
        # Check if docstring contains newlines
        if "\n" in docstring:
            # Use triple quotes for multi-line docstrings
            transformed_code += f'"""{docstring}"""\n\n'
        else:
            # Use single quotes for single-line docstrings
            transformed_code += f'"{docstring}"\n\n'

    # Add the rest of the code except imports and the original docstring
    remaining_nodes = []
    for node in tree.body:
        # Skip imports
        if isinstance(node, ast.Import | ast.ImportFrom):
            continue

        # Skip the original docstring
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue

        remaining_nodes.append(node)

    remaining_code = ast.unparse(ast.Module(body=remaining_nodes, type_ignores=[]))
    transformed_code += remaining_code

    # Ensure the directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Write the transformed code to the output file
    with open(output_file, "w") as f:
        f.write(transformed_code)

    return transformed_code
