import sys
from miasm.analysis.binary import Container
from miasm.analysis.machine import Machine
from miasm.core.locationdb import LocationDB
from miasm.ir.symbexec import SymbolicExecutionEngine
from miasm.expression.expression import ExprInt, ExprMem, ExprCond, ExprOp, ExprId
from miasm.core.asmblock import AsmCFG
from miasm.ir.ir import IRCFG
from future.utils import viewvalues

# Binary path and entry point
binary_path = "../../crashme"
main_address = 0x000000000022af70

def detect_null_pointer_patterns(ircfg_map):
    """
    Generic nil/null pointer dereference detection without assumptions
    """
    null_dereferences = []
    potential_null_flows = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    
                    # Pattern 1: Direct null pointer dereference - write to memory address 0
                    if isinstance(dst, ExprMem) and isinstance(dst.ptr, ExprInt):
                        if dst.ptr.arg == 0:
                            null_dereferences.append({
                                'type': 'direct_null_write',
                                'block': lbl,
                                'instruction': assignblk,
                                'address': dst.ptr.arg,
                                'cfg_addr': addr
                            })
                    
                    # Pattern 2: Write through a register that could be null
                    elif isinstance(dst, ExprMem) and isinstance(dst.ptr, ExprId):
                        potential_null_flows.append({
                            'type': 'register_deref',
                            'register': str(dst.ptr),
                            'block': lbl,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
                    
                    # Pattern 3: Assignment of null/zero to pointer registers
                    elif isinstance(dst, ExprId) and isinstance(src, ExprInt):
                        if src.arg == 0:
                            potential_null_flows.append({
                                'type': 'null_assignment',
                                'register': str(dst),
                                'block': lbl,
                                'instruction': assignblk,
                                'cfg_addr': addr
                            })
    
    return null_dereferences, potential_null_flows

def find_dangerous_memory_operations(ircfg_map):
    """
    Find memory operations that could be dangerous (writes to low addresses, null derefs, etc.)
    """
    dangerous_operations = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    # Check for memory writes
                    if isinstance(dst, ExprMem):
                        ptr = dst.ptr
                        
                        # Direct write to very low address (potential null/near-null deref)
                        if isinstance(ptr, ExprInt):
                            if ptr.arg < 0x1000:  # Low memory addresses
                                dangerous_operations.append({
                                    'type': 'low_memory_write',
                                    'address': ptr.arg,
                                    'block': lbl,
                                    'instruction': assignblk,
                                    'cfg_addr': addr,
                                    'severity': 'HIGH' if ptr.arg == 0 else 'MEDIUM'
                                })
                        
                        # Write through register that could be null
                        elif isinstance(ptr, ExprId):
                            dangerous_operations.append({
                                'type': 'register_deref',
                                'register': str(ptr),
                                'block': lbl,
                                'instruction': assignblk,
                                'cfg_addr': addr,
                                'severity': 'MEDIUM'
                            })
    
    return dangerous_operations

def find_conditional_paths(ircfg_map):
    """
    Find conditional branches and the paths they create
    """
    conditional_paths = []
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    # Look for conditional expressions
                    if isinstance(src, ExprCond):
                        conditional_paths.append({
                            'block': lbl,
                            'condition': src.cond,
                            'true_expr': src.src1,
                            'false_expr': src.src2,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
                    
                    # Look for comparison operations
                    elif isinstance(src, ExprOp) and src.op in ['==', '!=', '<', '>', '<=', '>=', 'CMP']:
                        # Extract comparison values
                        operands = []
                        for arg in src.args:
                            if isinstance(arg, ExprInt):
                                operands.append(('immediate', arg.arg))
                            elif isinstance(arg, ExprId):
                                operands.append(('register', str(arg)))
                            else:
                                operands.append(('expression', str(arg)))
                        
                        conditional_paths.append({
                            'block': lbl,
                            'operation': src.op,
                            'operands': operands,
                            'instruction': assignblk,
                            'cfg_addr': addr
                        })
    
    return conditional_paths

def trace_data_flow(ircfg_map):
    """
    Trace data flow to understand how values move through registers and memory
    """
    data_flows = []
    register_assignments = {}
    
    for addr, ircfg in ircfg_map.items():
        for lbl, irblock in ircfg.blocks.items():
            for assignblk in irblock:
                for dst, src in assignblk.items():
                    # Track register assignments
                    if isinstance(dst, ExprId):
                        reg_name = str(dst)
                        register_assignments[reg_name] = {
                            'source': src,
                            'block': lbl,
                            'cfg_addr': addr
                        }
                        
                        # Check if register is being set to zero or null
                        if isinstance(src, ExprInt) and src.arg == 0:
                            data_flows.append({
                                'type': 'null_assignment',
                                'register': reg_name,
                                'block': lbl,
                                'cfg_addr': addr
                            })
    
    return data_flows, register_assignments

def analyze_function_calls(ircfg_map, asm_cfg_map):
    """
    Analyze function calls and their relationships
    """
    function_calls = []
    
    for addr, asmcfg in asm_cfg_map.items():
        for block in asmcfg.blocks:
            # Look for call instructions
            for instr in block.lines:
                if instr.name.startswith('CALL') or 'call' in instr.name.lower():
                    function_calls.append({
                        'caller_addr': addr,
                        'instruction': str(instr),
                        'block': block,
                    })
    
    return function_calls

def correlate_vulnerabilities(dangerous_ops, conditional_paths, data_flows):
    """
    Correlate dangerous operations with conditional paths to find vulnerability triggers
    """
    vulnerabilities = []
    
    for dangerous_op in dangerous_ops:
        # Look for conditionals in the same or nearby blocks
        related_conditions = []
        
        for condition in conditional_paths:
            # Check if condition is in same CFG or related block
            if condition['cfg_addr'] == dangerous_op['cfg_addr']:
                related_conditions.append(condition)
        
        if related_conditions:
            vulnerabilities.append({
                'dangerous_operation': dangerous_op,
                'triggering_conditions': related_conditions,
                'vulnerability_type': 'conditional_vulnerability'
            })
        else:
            vulnerabilities.append({
                'dangerous_operation': dangerous_op,
                'triggering_conditions': [],
                'vulnerability_type': 'unconditional_vulnerability'
            })
    
    return vulnerabilities

def disassemble_and_analyze(machine, mdis, start_addr, follow_calls=True):
    """
    Comprehensive disassembly and analysis
    """
    todo = [(mdis, start_addr)]
    done = set()
    ircfg_map = {}
    asm_cfg_map = {}
    
    print(f"Starting comprehensive analysis from: {hex(start_addr)}")
    
    while todo:
        mdis, addr = todo.pop(0)
        if addr in done:
            continue
        done.add(addr)
        
        try:
            asmcfg = mdis.dis_multiblock(addr)
            print(f"Analyzing block at {hex(addr)}: {len(asmcfg.blocks)} basic blocks")
            
            lifter = machine.lifter_model_call(mdis.loc_db)
            ircfg = lifter.new_ircfg_from_asmcfg(asmcfg)
            ircfg_map[addr] = ircfg
            asm_cfg_map[addr] = asmcfg
            
            # Follow function calls
            if follow_calls:
                for block in asmcfg.blocks:
                    instr = block.get_subcall_instr()
                    if instr:
                        for dest in instr.getdstflow(mdis.loc_db):
                            if dest.is_loc():
                                offset = mdis.loc_db.get_location_offset(dest.loc_key)
                                if offset and offset not in done:
                                    todo.append((mdis, offset))
                                    
        except Exception as e:
            print(f"Error analyzing {hex(addr)}: {e}")
            continue
    
    return ircfg_map, asm_cfg_map

def main():
    if len(sys.argv) > 1:
        global binary_path, main_address
        binary_path = sys.argv[1]
        if len(sys.argv) > 2:
            main_address = int(sys.argv[2], 16)
    
    print("=== MIASM Vulnerability Discovery ===")
    print(f"Target: {binary_path}")
    print(f"Entry point: {hex(main_address)}")
    
    # Initialize MIASM
    loc_db = LocationDB()
    machine = Machine("x86_64")
    
    try:
        with open(binary_path, "rb") as f:
            container = Container.from_stream(f, loc_db)
        print("SUCCESS: Binary loaded successfully")
    except Exception as e:
        print(f"ERROR: Failed to load binary: {e}")
        return
    
    mdis = machine.dis_engine(container.bin_stream, loc_db=loc_db)
    
    # Perform comprehensive analysis
    print("\n=== Phase 1: Disassembly and IR Generation ===")
    ircfg_map, asm_cfg_map = disassemble_and_analyze(machine, mdis, main_address)
    
    if not ircfg_map:
        print("ERROR: No analyzable code found")
        return
    
    print(f"SUCCESS: Analyzed {len(ircfg_map)} code segments")
    
    # Phase 2: Null pointer dereference detection
    print("\n=== Phase 2: Null Pointer Dereference Detection ===")
    null_derefs, potential_nulls = detect_null_pointer_patterns(ircfg_map)
    
    if null_derefs:
        print(f"CRITICAL: FOUND {len(null_derefs)} DIRECT NULL POINTER DEREFERENCES:")
        for i, deref in enumerate(null_derefs, 1):
            print(f"  {i}. {deref['type']} at block {deref['block']}")
            print(f"     Instruction: {deref['instruction']}")
            print(f"     Memory address: {hex(deref['address'])}")
    
    if potential_nulls:
        print(f"WARNING: Found {len(potential_nulls)} potential null-related operations:")
        null_assigns = [p for p in potential_nulls if p['type'] == 'null_assignment']
        reg_derefs = [p for p in potential_nulls if p['type'] == 'register_deref']
        
        if null_assigns:
            print(f"   - {len(null_assigns)} null assignments to registers")
        if reg_derefs:
            print(f"   - {len(reg_derefs)} memory dereferences through registers")
    
    # Phase 3: Find dangerous operations
    print("\n=== Phase 3: General Dangerous Operation Detection ===")
    dangerous_ops = find_dangerous_memory_operations(ircfg_map)
    
    for op in dangerous_ops:
        print(f"ALERT {op['severity']} - {op['type']}")
        if 'address' in op:
            print(f"   Memory address: {hex(op['address'])}")
        if 'register' in op:
            print(f"   Through register: {op['register']}")
        print(f"   Location: Block {op['block']} in CFG {hex(op['cfg_addr'])}")
    
    # Phase 4: Conditional analysis
    print(f"\n=== Phase 4: Conditional Path Analysis ===")
    conditional_paths = find_conditional_paths(ircfg_map)
    
    print(f"Found {len(conditional_paths)} conditional operations:")
    for i, cond in enumerate(conditional_paths[:10]):  # Show first 10
        if 'operation' in cond:
            print(f"  {i+1}. {cond['operation']} operation with operands: {cond['operands']}")
        else:
            print(f"  {i+1}. Conditional branch in block {cond['block']}")
    
    # Phase 5: Data flow analysis
    print(f"\n=== Phase 5: Data Flow Analysis ===")
    data_flows, register_assignments = trace_data_flow(ircfg_map)
    
    # Phase 6: Vulnerability correlation  
    print(f"\n=== Phase 6: Vulnerability Analysis ===")
    vulnerabilities = correlate_vulnerabilities(dangerous_ops, conditional_paths, data_flows)
    
    # Combine all findings
    all_vulnerabilities = vulnerabilities.copy()
    
    # Add direct null dereferences as high-priority vulnerabilities
    for null_deref in null_derefs:
        all_vulnerabilities.append({
            'dangerous_operation': null_deref,
            'triggering_conditions': [],
            'vulnerability_type': 'direct_null_dereference'
        })
    
    print(f"\nVULNERABILITY ANALYSIS REPORT:")
    print(f"VULNERABILITY ANALYSIS REPORT:")
    print(f"Found {len(all_vulnerabilities)} potential vulnerabilities")
    
    for i, vuln in enumerate(all_vulnerabilities, 1):
        dangerous_op = vuln['dangerous_operation']
        print(f"\n--- Vulnerability #{i} ---")
        print(f"Type: {vuln['vulnerability_type']}")
        if 'severity' in dangerous_op:
            print(f"Severity: {dangerous_op['severity']}")
        print(f"Location: Block {dangerous_op['block']}")
        print(f"Operation: {dangerous_op['type']}")
        
        if vuln['triggering_conditions']:
            print("Triggering conditions:")
            for cond in vuln['triggering_conditions']:
                if 'operands' in cond:
                    print(f"  - {cond['operation']} with operands: {cond['operands']}")
                elif 'condition' in cond:
                    print(f"  - Conditional: {cond['condition']}")
            print("This is a CONDITIONAL vulnerability")
        else:
            if vuln['vulnerability_type'] == 'direct_null_dereference':
                print("This is a DIRECT NULL POINTER DEREFERENCE")
            else:
                print("This appears to be an UNCONDITIONAL vulnerability")
    
    # Generate output files
    try:
        full_cfg = AsmCFG(mdis.loc_db)
        for blocks in viewvalues(asm_cfg_map):
            full_cfg += blocks
        
        with open('vulnerability_analysis.dot', 'w') as f:
            f.write(full_cfg.dot(offset=True))
        print(f"SUCCESS: Control flow graph saved to vulnerability_analysis.dot")
    except Exception as e:
        print(f"ERROR: Could not generate CFG: {e}")
    
    print(f"\n=== Analysis Complete ===")
    if vulnerabilities:
        print("ALERT: VULNERABILITIES DETECTED - Manual review recommended")
    else:
        print("INFO: No obvious vulnerabilities found in static analysis")

if __name__ == "__main__":
    main()