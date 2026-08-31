package com.appshield.engine.dex

/**
 * Phase 2: Control Flow Flattening (CFF)
 * Rewrites a method's logic into a single 'switch' statement inside a 'while' loop.
 */
class ControlFlowEngine {

    fun flatten(methodName: String, instructions: List<String>): List<String> {
        println("   [Engine] Flattening control flow for method: $methodName")
        
        val flattened = mutableListOf<String>()
        flattened.add("int state = 0;")
        flattened.add("while (state != -1) {")
        flattened.add("    switch (state) {")
        
        instructions.forEachIndexed { index, instr ->
            flattened.add("        case $index:")
            flattened.add("            execute('$instr');")
            flattened.add("            state = ${if (index == instructions.lastIndex) -1 else index + 1};")
            flattened.add("            break;")
        }
        
        flattened.add("    }")
        flattened.add("}")
        return flattened
    }
}
