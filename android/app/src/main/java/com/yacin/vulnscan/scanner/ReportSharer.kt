package com.yacin.vulnscan.scanner

import android.content.Context
import android.content.Intent
import androidx.core.content.FileProvider
import java.io.File

/** Fires Android share intents so reports can be sent to any app (incl. AI apps). */
object ReportSharer {

    /** Share plain text (report or AI prompt) via the system sharesheet. */
    fun shareText(context: Context, title: String, text: String) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, title)
            putExtra(Intent.EXTRA_TEXT, text)
        }
        context.startActivity(
            Intent.createChooser(send, title).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }

    /** Write the report to a .md file in cache and share it as an attachment. */
    fun shareFile(context: Context, fileName: String, text: String) {
        val dir = File(context.cacheDir, "reports").apply { mkdirs() }
        val file = File(dir, fileName)
        file.writeText(text)
        val uri = FileProvider.getUriForFile(
            context, "${context.packageName}.fileprovider", file
        )
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/markdown"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(
            Intent.createChooser(send, fileName).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }
}
