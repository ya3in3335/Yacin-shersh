package com.strykerx.lab.scanner.apk

import org.jf.dexlib2.AccessFlags
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.Instruction
import org.jf.dexlib2.iface.instruction.OneRegisterInstruction
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.instruction.RegisterRangeInstruction
import org.jf.dexlib2.iface.instruction.ThreeRegisterInstruction
import org.jf.dexlib2.iface.instruction.TwoRegisterInstruction
import org.jf.dexlib2.iface.instruction.formats.Instruction35c
import org.jf.dexlib2.iface.reference.MethodReference
import java.io.File

/**
 * Taint-based data-flow analysis over DEX bytecode (dexlib2). This goes beyond
 * "a source and a sink appear in the same method": it tracks the tainted VALUE
 * through registers — from an attacker-controllable source (Intent/URI) along
 * moves, field/array loads, string building and helper calls — and reports a
 * CONFIRMED tainted path only when a tainted register is actually passed into a
 * dangerous sink. It also follows taint ONE+ hop into app-internal methods
 * (inter-procedural), seeding the callee's parameters from the tainted arguments.
 *
 * Honest scope: this is a lightweight, flow-insensitive register taint with
 * bounded inter-procedural propagation — not a full, path-sensitive solver like
 * FlowDroid, and it over-approximates return taint for helper calls. It proves a
 * value-flow path from an attacker-reachable entry point to a sink; it does NOT
 * prove end impact (auth bypass, data disclosure, financial action) — that still
 * needs a runtime PoC. Fully offline; the app is never executed.
 */
object DexFlowAnalyzer {

    data class FlowFinding(
        val component: String,
        val method: String,
        val source: String,
        val sink: String,
        val tainted: Boolean,   // true = taint reached the sink; false = co-occurrence only
        val chain: String?      // call chain for inter-procedural hits
    )

    private const val MAX_CLASSES = 600
    private const val MAX_INSTRUCTIONS = 4_000_000
    private const val MAX_FINDINGS = 60
    private const val MAX_DEPTH = 3

    private val SOURCE_NAMES = setOf(
        "getStringExtra", "getIntExtra", "getLongExtra", "getBooleanExtra",
        "getExtras", "getParcelableExtra", "getSerializableExtra", "getCharSequenceExtra",
        "getStringArrayListExtra", "getData", "getDataString",
        "getQueryParameter", "getQueryParameters", "getLastPathSegment", "getPathSegments"
    )

    // definingClass -> (methodName -> human sink label)
    private val SINKS: List<Triple<String, String, String>> = listOf(
        Triple("Landroid/database/sqlite/SQLiteDatabase;", "rawQuery", "SQL query (SQL injection) [CWE-89]"),
        Triple("Landroid/database/sqlite/SQLiteDatabase;", "execSQL", "SQL execution (SQL injection) [CWE-89]"),
        Triple("Landroid/webkit/WebView;", "loadUrl", "WebView.loadUrl (URL/content injection) [CWE-749]"),
        Triple("Landroid/webkit/WebView;", "loadData", "WebView.loadData (content injection) [CWE-749]"),
        Triple("Landroid/webkit/WebView;", "loadDataWithBaseURL", "WebView.loadDataWithBaseURL [CWE-749]"),
        Triple("Ljava/lang/Runtime;", "exec", "Runtime.exec (command execution) [CWE-78]"),
        Triple("Ljava/lang/ProcessBuilder;", "start", "ProcessBuilder (command execution) [CWE-78]"),
        Triple("Ldalvik/system/DexClassLoader;", "<init>", "Dynamic code loading [CWE-494]"),
        Triple("Landroid/content/Context;", "startActivity", "Intent redirection (startActivity) [CWE-926]"),
        Triple("Landroid/content/Context;", "sendBroadcast", "Intent redirection (sendBroadcast) [CWE-926]"),
        Triple("Ljava/io/File;", "<init>", "File path from input (path traversal) [CWE-22]")
    )

    private fun sinkLabel(definingClass: String, name: String): String? =
        SINKS.firstOrNull { it.first == definingClass && it.second == name }?.third

    /** Per-analysis mutable state (budgets + class index). */
    private class Ctx(val classMap: Map<String, ClassDef>) {
        var instructions = 0L
        val out = ArrayList<FlowFinding>()
        fun budgetLeft() = instructions < MAX_INSTRUCTIONS && out.size < MAX_FINDINGS
    }

    /** @param exportedClasses dotted class names of exported components. */
    fun analyze(apk: File, exportedClasses: Set<String>): List<FlowFinding> {
        if (exportedClasses.isEmpty()) return emptyList()
        val wanted = exportedClasses.map { "L" + it.replace('.', '/') + ";" }.toHashSet()

        return runCatching {
            val container = DexFileFactory.loadDexContainer(apk, Opcodes.getDefault())
            val classMap = HashMap<String, ClassDef>()
            for (entryName in container.dexEntryNames) {
                val dex = container.getEntry(entryName)?.dexFile ?: continue
                for (cls in dex.classes) {
                    if (classMap.size >= MAX_CLASSES * 50) break
                    classMap.putIfAbsent(cls.type, cls)
                }
            }
            val ctx = Ctx(classMap)
            var scanned = 0
            for (type in wanted) {
                if (!ctx.budgetLeft() || scanned >= MAX_CLASSES) break
                val cls = classMap[type] ?: continue
                scanned++
                val dotted = type.removePrefix("L").removeSuffix(";").replace('/', '.')
                for (m in cls.methods) {
                    if (!ctx.budgetLeft()) break
                    scanMethod(ctx, dotted, m, seeded = emptySet(), depth = 0, chain = "", visited = HashSet())
                }
            }
            ctx.out
        }.getOrDefault(emptyList())
    }

    /**
     * Scans one method, tracking tainted registers. [seeded] are registers tainted
     * on entry (used for inter-procedural callees). Adds findings to ctx.out.
     */
    private fun scanMethod(
        ctx: Ctx, component: String, method: Method,
        seeded: Set<Int>, depth: Int, chain: String, visited: MutableSet<String>
    ) {
        val impl = method.implementation ?: return
        val sig = method.definingClass + "->" + method.name
        if (!visited.add(sig + "#" + depth)) return

        val tainted = HashSet(seeded)
        var pendingResultTaint = false
        var sawSource = seeded.isNotEmpty()
        var sourceName = if (seeded.isNotEmpty()) "tainted argument" else ""
        val sinksSeen = linkedMapOf<String, Boolean>() // label -> everTaintedHere (for co-occurrence fallback)

        for (insn in impl.instructions) {
            if (ctx.instructions++ >= MAX_INSTRUCTIONS) break
            // Normalize to UPPER_SNAKE so matching works whether the opcode string is
            // the enum constant name ("MOVE_RESULT") or the dalvik mnemonic ("move-result").
            val op = (insn.opcode.name ?: "").uppercase().replace('-', '_')

            if (op.startsWith("INVOKE")) {
                val ref = (insn as? ReferenceInstruction)?.reference as? MethodReference
                if (ref == null) { pendingResultTaint = false; continue }
                val args = invokeArgs(insn)
                val anyTainted = args.any { it in tainted }
                val name = ref.name
                val defClass = ref.definingClass

                // Source: result becomes tainted.
                if (name in SOURCE_NAMES) {
                    pendingResultTaint = true
                    sawSource = true
                    if (sourceName.isEmpty()) sourceName = name
                    continue
                }

                // Sink?
                val label = sinkLabel(defClass, name)
                if (label != null) {
                    val wasTainted = anyTainted
                    sinksSeen[label] = (sinksSeen[label] ?: false) || wasTainted
                    if (wasTainted) {
                        addFinding(ctx, component, method.name, sourceName.ifEmpty { "Intent/URI" }, label, true,
                            if (chain.isEmpty()) null else chain.trimStart('>', ' '))
                    }
                    pendingResultTaint = false
                    continue
                }

                // Inter-procedural: follow taint into an app-internal method.
                if (anyTainted && depth < MAX_DEPTH && ctx.budgetLeft()) {
                    val callee = resolveCallee(ctx, defClass, ref)
                    if (callee != null) {
                        val seed = seedCalleeParams(callee, args, tainted)
                        if (seed.isNotEmpty()) {
                            scanMethod(ctx, component, callee, seed, depth + 1,
                                chain + " > " + defClass.substringAfterLast('/').removeSuffix(";") + "." + name,
                                visited)
                        }
                    }
                }
                // Conservatively, a call with tainted input may return tainted data.
                pendingResultTaint = anyTainted
                continue
            }

            when {
                op.startsWith("MOVE_RESULT") -> {
                    val d = regA(insn)
                    if (d != null) { if (pendingResultTaint) tainted.add(d) else tainted.remove(d) }
                    pendingResultTaint = false
                }
                op.startsWith("MOVE_EXCEPTION") -> { pendingResultTaint = false }
                op.startsWith("MOVE") -> { // MOVE / MOVE_OBJECT / MOVE_WIDE / MOVE_FROM16 / MOVE_16
                    val d = regA(insn); val s = regB(insn)
                    if (d != null) { if (s != null && s in tainted) tainted.add(d) else tainted.remove(d) }
                    pendingResultTaint = false
                }
                op.startsWith("CONST") -> { regA(insn)?.let { tainted.remove(it) }; pendingResultTaint = false }
                op.startsWith("IGET") || op.startsWith("AGET") || op.startsWith("SGET") -> {
                    val d = regA(insn); val b = regB(insn); val c = regC(insn)
                    val fromTainted = (b != null && b in tainted) || (c != null && c in tainted)
                    if (d != null) { if (fromTainted) tainted.add(d) else tainted.remove(d) }
                    pendingResultTaint = false
                }
                op.startsWith("IPUT") || op.startsWith("APUT") -> {
                    // store src(regA) into object/array(regB): taint the container.
                    val src = regA(insn); val base = regB(insn)
                    if (src != null && base != null && src in tainted) tainted.add(base)
                    pendingResultTaint = false
                }
                else -> {
                    // binop/unop/conversions: dest(regA) tainted if any input reg is tainted.
                    val d = regA(insn); val b = regB(insn); val c = regC(insn)
                    if (d != null && (insn is TwoRegisterInstruction || insn is ThreeRegisterInstruction)) {
                        val fromTainted = (b != null && b in tainted) || (c != null && c in tainted)
                        if (fromTainted) tainted.add(d) else tainted.remove(d)
                    }
                    pendingResultTaint = false
                }
            }
        }

        // Co-occurrence fallback (POTENTIAL): a source and a sink both appear but
        // taint did not link them — still worth a lead, at lower confidence.
        if (depth == 0 && sawSource) {
            for ((label, everTainted) in sinksSeen) {
                if (!everTainted) {
                    addFinding(ctx, component, method.name, sourceName.ifEmpty { "Intent/URI" }, label, false, null)
                }
            }
        }
    }

    private fun addFinding(
        ctx: Ctx, component: String, method: String, source: String, sink: String,
        tainted: Boolean, chain: String?
    ) {
        if (ctx.out.size >= MAX_FINDINGS) return
        // De-dup on component+sink+tainted.
        if (ctx.out.any { it.component == component && it.sink == sink && it.tainted == tainted }) return
        ctx.out += FlowFinding(component, method, source, sink, tainted, chain)
    }

    private fun resolveCallee(ctx: Ctx, definingClass: String, ref: MethodReference): Method? {
        val cls = ctx.classMap[definingClass] ?: return null
        val want = ref.parameterTypes.size
        return cls.methods.firstOrNull {
            it.name == ref.name && it.parameterTypes.size == want && it.implementation != null
        }
    }

    /** Maps tainted caller argument registers to the callee's parameter registers. */
    private fun seedCalleeParams(callee: Method, callerArgs: List<Int>, tainted: Set<Int>): Set<Int> {
        val impl = callee.implementation ?: return emptySet()
        val isStatic = (callee.accessFlags and AccessFlags.STATIC.value) != 0
        val paramCount = callee.parameterTypes.size
        val thisCount = if (isStatic) 0 else 1
        val slots = paramCount + thisCount
        if (slots <= 0) return emptySet()
        val firstParamReg = impl.registerCount - slots
        if (firstParamReg < 0) return emptySet()
        val seed = HashSet<Int>()
        // callerArgs is parallel to callee incoming slots (approx: 1 word per slot).
        for (idx in callerArgs.indices) {
            if (idx >= slots) break
            if (callerArgs[idx] in tainted) seed.add(firstParamReg + idx)
        }
        return seed
    }

    // --- register / argument accessors ---

    private fun regA(insn: Instruction): Int? = (insn as? OneRegisterInstruction)?.registerA
    private fun regB(insn: Instruction): Int? = (insn as? TwoRegisterInstruction)?.registerB
    private fun regC(insn: Instruction): Int? = (insn as? ThreeRegisterInstruction)?.registerC

    private fun invokeArgs(insn: Instruction): List<Int> = when (insn) {
        is Instruction35c -> {
            val c = insn.registerCount
            listOf(insn.registerC, insn.registerD, insn.registerE, insn.registerF, insn.registerG).take(c)
        }
        is RegisterRangeInstruction -> (0 until insn.registerCount).map { insn.startRegister + it }
        else -> emptyList()
    }
}
