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

class VirusDetector(ast.NodeVisitor):
    def __init__(self):
        self.functions: defaultdict[str, list[CodeSegment]] = defaultdict(list)
        self.calls: list[CodeSegment] = []
        self.malware_segments: list[CodeSegment] = []

    def is_malware_function(self, node: ast.FunctionDef) -> bool:
        file_access = [
            n for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and any(method in n.func.attr for method in ['glob', 'iterdir', 'rglob'])
        ]

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

        return bool(writes and (self_reads or file_access or exec_calls))

    def visit_FunctionDef(self, node: ast.FunctionDef):
        is_malware = self.is_malware_function(node)
        segment = CodeSegment(
            start = node.lineno - 1,
            end = node.end_lineno,
            is_malware = is_malware,
            isfunc = True,
            name = node.name
        )
        self.functions[node.name].append(segment)
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

    def analyze_code(self):
        malwares: defaultdict[str, list[CodeSegment]] = defaultdict(list)
        for name, func_segments in self.functions.items():
            for segment in func_segments:
                if segment.is_malware: malwares[name].append(segment)

        for segments in malwares.values():
            self.malware_segments.extend(segments)

        for call in self.calls:
            if call.name in malwares:
                active_malware = False
                for func_segment in malwares[call.name]:
                    if call.start > func_segment.start:
                        overwritten = False
                        for clean_segment in self.functions[call.name]:
                            if (not clean_segment.is_malware and func_segment.start < clean_segment.start < call.start):
                                overwritten = True
                                break
                        if not overwritten:
                            active_malware = True
                            break

                if active_malware: self.malware_segments.append(call)

def remove_malware(file_lns: list[str], malware_segments: list[CodeSegment]) -> list[str]:
    malware_segments = sorted(malware_segments, key=lambda x: x.start, reverse=True)

    for seg in malware_segments:
        if seg.isfunc: file_lns[seg.start:seg.end + 1] = ''
        elif seg.start < len(file_lns):
            line = file_lns[seg.start]
            leading_whitespace = line[:len(line) - len(line.lstrip())]

            calls = [c.strip() for c in line.split(';') if c.strip()]
            calls_cur = [c for c in calls if not re.fullmatch(rf'\b{re.escape(seg.name)}\s*\(.*?\)', c)]
            if calls_cur: file_lns[seg.start] = leading_whitespace + ' ; '.join(calls_cur)
            else: file_lns.pop(seg.start)

    return file_lns


def cure_py(file: pathlib.Path):
    try:
        data = file.read_text()
        tree = ast.parse(data)

        detector = VirusDetector()
        detector.visit(tree)
        detector.analyze_code()

        if not detector.malware_segments: return
        data_lines = data.splitlines()
        cleaned_lines = remove_malware(data_lines, detector.malware_segments)
        cleaned_data = '\n'.join(cleaned_lines).strip()
        file.write_text(cleaned_data)

        print(f"Cleaned {file}:")
        print(f"- Removed {len(detector.malware_segments)} malicious segments")

    except Exception as e:
        print(f"Error processing {file}: {e}")

def main():
    for file in pathlib.Path(__file__).absolute().parent.glob('*.py'): cure_py(file)

main()