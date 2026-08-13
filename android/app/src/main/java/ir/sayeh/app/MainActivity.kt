package ir.sayeh.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.viewmodel.compose.viewModel
import ir.sayeh.app.ui.SayehScreen
import ir.sayeh.app.ui.theme.SayehTheme

class MainActivity : ComponentActivity() {
    private var incomingText by mutableStateOf<String?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        incomingText = sharedText(intent)

        setContent {
            SayehTheme {
                val sayehViewModel: SayehViewModel = viewModel()
                LaunchedEffect(incomingText) {
                    incomingText?.let(sayehViewModel::receive)
                    incomingText = null
                }
                SayehScreen(
                    viewModel = sayehViewModel,
                    onShare = ::shareText,
                    onCopy = ::copySensitive,
                    onPaste = ::clipboardText,
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        incomingText = sharedText(intent)
    }

    private fun shareText(text: String) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, text)
        }
        startActivity(Intent.createChooser(send, getString(R.string.share_action)))
    }

    private fun copySensitive(text: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(getString(R.string.app_name), text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        clipboard.setPrimaryClip(clip)
        val result = if (clipboardText() == text) R.string.copied else R.string.copy_changed
        Toast.makeText(this, result, Toast.LENGTH_LONG).show()
    }

    private fun clipboardText(): String? {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        return clipboard.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()
    }

    private fun sharedText(intent: Intent?): String? {
        if (intent?.action != Intent.ACTION_SEND || intent.type != "text/plain") {
            return null
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getStringExtra(Intent.EXTRA_TEXT)
        } else {
            @Suppress("DEPRECATION")
            intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
        }
    }
}
