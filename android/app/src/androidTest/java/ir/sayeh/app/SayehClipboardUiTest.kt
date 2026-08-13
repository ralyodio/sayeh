package ir.sayeh.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import ir.sayeh.ffi.revealPasswordMessage
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class SayehClipboardUiTest {
    @get:Rule
    val compose = createAndroidComposeRule<MainActivity>()

    @Test
    fun copyButtonPreservesCarriersAndTheUiOpensThePaste() {
        val cover = "سلام خوبی؟"
        val secret = "synthetic clipboard message"
        val clipboard = compose.activity.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val original = AtomicReference<ClipData?>()
        compose.runOnUiThread { original.set(clipboard.primaryClip) }

        try {
            compose.onNodeWithTag("cover_input").performTextInput(cover)
            compose.onNodeWithTag("secret_input").performTextInput(secret)
            compose.onNodeWithTag("hide_button").performClick()
            compose.waitUntil(15_000) {
                compose.onAllNodesWithTag("hidden_output").fetchSemanticsNodes().isNotEmpty()
            }
            compose.onNodeWithTag("hidden_copy").performClick()

            val copied = AtomicReference<String>()
            compose.runOnUiThread {
                copied.set(
                    clipboard.primaryClip
                        ?.getItemAt(0)
                        ?.coerceToText(compose.activity)
                        ?.toString()
                        .orEmpty(),
                )
            }
            assertTrue(copied.get().length > cover.length)
            assertEquals(secret, revealPasswordMessage(copied.get(), "").text)

            compose.onNodeWithTag("open_tab").performClick()
            compose.onNodeWithTag("paste_button").performClick()
            compose.onNodeWithTag("open_button").performClick()
            compose.waitUntil(15_000) {
                compose.onAllNodesWithTag("opened_output").fetchSemanticsNodes().isNotEmpty()
            }
            compose.onNodeWithTag("opened_output").assertTextContains(secret)
        } finally {
            compose.runOnUiThread {
                original.get()?.let(clipboard::setPrimaryClip) ?: clipboard.clearPrimaryClip()
            }
        }
    }
}
