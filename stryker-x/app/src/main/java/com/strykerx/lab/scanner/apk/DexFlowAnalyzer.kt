package com.strykerx.lab.scanner.apk

import org.jf.dexlib2.Opcodes
import org.jf.dexlib2.DexFileFactory
import org.jf.dexlib2.iface.ClassDef
import org.jf.dexlib2.iface.Method
import org.jf.dexlib2.iface.instruction.ReferenceInstruction
import org.jf.dexlib2.iface.reference.MethodReference
import java.io.File

/**
 * Bytecode data-flow (reachability) analysis via dexlib2 — the disassembly engine
 * behind baksmali/apktool. Where the string scan only proves a risky API *exists*,
 * this proves a *reachable path*: an exported component method that both reads
 * attacker-controllable input (an Intent/URI source) and calls a dangerous sink
 * (SQL, WebView, command execution, dynamic loading) in the same method.
 *
 * This is intra-method source+sink co-occurrence, not full inter-procedural taint:
 * it raises confidence from "potential" to "a path from an attacker-reachable
 * entry point to a sink exists in the bytecode". Proving the end impact (auth
 * bypass, data disclosure, financial action) still needs a runtime PoC — this does
 * not claim that. Fully offline; the app is never executed.
 */
object DexFlowAnalyzer {

    data class FlowFinding(
        val component: String,  // exported class (dotted)
        val method: String,     // method where source and sink meet
        val source: String,     // attacker-controllable input API
        val sink: String        // dangerous sink reached
    )

    private const val MAX_CLASSES = 400
    private const val MAX_INSTRUCTIONS = 3_000_000
    private const val MAX_FINDINGS = 40

    /** Methods that return attacker-controllable data from an Intent/URI. */
    private val SOURCE_NAMES = setOf(
        "getStringExtra", "getIntExtra", "getLongExtra", "getBooleanExtra",
        "getExtras", "getParcelableExtra", "getSerializableExtra",
        "getStringArrayListExtra", "getData", "getDataString",
        "getQueryParameter", "getQueryParameters", "getLastPathSegment"
    )

    /** Dangerous sinks, keyed by "DefiningClass->method", with a human label. */
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

    /** @param exportedClasses dotted class names of exported components. */
    fun analyze(apk: File, exportedClasses: Set<String>): List<FlowFinding> {
        if (exportedClasses.isEmpty()) return emptyList()
        val wanted = exportedClasses.map { "L" + it.replace('.', '/') + ";" }.toHashSet()
        val out = ArrayList<FlowFinding>()
        var instructions = 0L
        var classesSeen = 0

        runCatching {
            val container = DexFileFactory.loadDexContainer(apk, Opcodes.getDefault())
            for (entryName in container.dexEntryNames) {
                if (out.size >= MAX_FINDINGS) break
                val dex = container.getEntry(entryName)?.dexFile ?: continue
                for (cls: ClassDef in dex.classes) {
                    if (out.size >= MAX_FINDINGS || instructions >= MAX_INSTRUCTIONS) break
                    if (cls.type !in wanted) continue
                    if (++classesSeen > MAX_CLASSES) break
                    val dotted = cls.type.removePrefix("L").removeSuffix(";").replace('/', '.')
                    for (m: Method in cls.methods) {
                        val impl = m.implementation ?: continue
                        var source: String? = null
                        val sinksHit = linkedMapOf<String, String>() // label -> sink method
                        for (insn in impl.instructions) {
                            if (++instructions >= MAX_INSTRUCTIONS) break
                            val ref = (insn as? ReferenceInstruction)?.reference as? MethodReference ?: continue
                            val callName = ref.name
                            if (source == null && callName in SOURCE_NAMES) source = callName
                            for ((cls2, method2, label) in SINKS) {
                                if (callName == method2 && ref.definingClass == cls2) sinksHit[label] = method2
                            }
                        }
                        val src = source
                        if (src != null && sinksHit.isNotEmpty()) {
                            for ((label, _) in sinksHit) {
                                if (out.size >= MAX_FINDINGS) break
                                out += FlowFinding(dotted, m.name, src, label)
                            }
                        }
                    }
                }
            }
        }
        return out
    }
}
