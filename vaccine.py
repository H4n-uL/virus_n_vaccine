import ast, re, pathlib
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class CodeSegment:
    start: int
    end: int
    is_malware: bool
    isfunc: bool
    name: str = ''

class AntivirusEngine(ast.NodeVisitor):
    def __init__(self):
        self.funcs: defaultdict[str, list[CodeSegment]] = defaultdict(list)
        self.calls: list[CodeSegment] = []
        self.malseg: list[CodeSegment] = []

    def is_malware_function(self, node: ast.FunctionDef) -> bool:
        writes = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and 'write' in n.func.attr
        ]

        self_reads = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and 'getsource' in n.func.attr
        ]

        exec_calls = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'exec'
        ]

        eval_calls = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
            and n.func.id == 'eval'
        ]

        return bool(writes and (self_reads or exec_calls or eval_calls))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        is_malware = self.is_malware_function(node)
        segment = CodeSegment(
            start = node.lineno - 1,
            end = node.end_lineno,
            is_malware = is_malware,
            isfunc = True,
            name = node.name
        )
        self.funcs[node.name].append(segment)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if isinstance(node.func, ast.Name):
            segment = CodeSegment(
                start = node.lineno - 1,
                end = node.end_lineno,
                is_malware = False,
                isfunc = False,
                name = node.func.id
            )
            self.calls.append(segment)
        self.generic_visit(node)

    def analyze_code(self, data: str):
        self.visit(ast.parse(data))
        malwares: defaultdict[str, list[CodeSegment]] = defaultdict(list)
        for name, func_segments in self.funcs.items():
            for segment in func_segments:
                if segment.is_malware: malwares[name].append(segment)

        for segments in malwares.values():
            self.malseg.extend(segments)

        for call in self.calls:
            if call.name in malwares:
                active_malware = False
                for func_segment in malwares[call.name]:
                    if call.start > func_segment.start:
                        overwritten = False
                        for clean_segment in self.funcs[call.name]:
                            if (not clean_segment.is_malware and func_segment.start < clean_segment.start < call.start):
                                overwritten = True
                                break
                        if not overwritten:
                            active_malware = True
                            break

                if active_malware: self.malseg.append(call)

    def remove_malware(self, data: str) -> str:
        data_lines = data.splitlines()
        self.malseg = sorted(self.malseg, key=lambda x: x.start, reverse=True)

        for seg in self.malseg:
            if seg.isfunc: data_lines[seg.start:seg.end + 1] = ''
            elif seg.start < len(data_lines):
                line = data_lines[seg.start]
                leading_whitespace = line[:len(line) - len(line.lstrip())]

                calls = [c.strip() for c in line.split(';') if c.strip()]
                calls_cur = [c for c in calls if not re.fullmatch(rf'\b{re.escape(seg.name)}\s*\(.*?\)', c)]
                if calls_cur: data_lines[seg.start] = leading_whitespace + ' ; '.join(calls_cur)
                else: data_lines.pop(seg.start)

        return '\n'.join(data_lines).strip()

def cure_py(file: pathlib.Path):
    try:
        data = file.read_text()

        antivirus = AntivirusEngine()
        antivirus.analyze_code(data)
        if not antivirus.malseg: return
        data_clean = antivirus.remove_malware(data)

        if not data_clean:
            file.unlink()
            print(f"Removed {file} with {len(antivirus.malseg)} malicious segments")
        else:
            file.write_text(data_clean)
            print(f"Cleaned {file} with {len(antivirus.malseg)} malicious segments")

    except Exception as e:
        print(f"Error processing {file}: {e}")

def main():
    for file in pathlib.Path(__file__).absolute().parent.glob('*.py'): cure_py(file)

main()