package ir.sayeh.app.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

private val LightColors = lightColorScheme(
    primary = Color(0xFF1B5B4C),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD5EBE2),
    onPrimaryContainer = Color(0xFF092E26),
    secondary = Color(0xFF4A635B),
    surface = Color(0xFFF9FAF7),
    surfaceVariant = Color(0xFFE2E8E3),
    background = Color(0xFFF7F7F4),
    error = Color(0xFFBA1A1A),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFA9D5C5),
    onPrimary = Color(0xFF00382E),
    primaryContainer = Color(0xFF134E41),
    onPrimaryContainer = Color(0xFFC5EBDD),
    secondary = Color(0xFFB4CCC3),
    surface = Color(0xFF121714),
    surfaceVariant = Color(0xFF3F4945),
    background = Color(0xFF101311),
    error = Color(0xFFFFB4AB),
)

@Composable
fun SayehTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val colors = if (dark) DarkColors else LightColors
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            @Suppress("DEPRECATION")
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
                window.statusBarColor = colors.background.toArgb()
                window.navigationBarColor = colors.background.toArgb()
            }
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !dark
                isAppearanceLightNavigationBars = !dark
            }
        }
    }
    MaterialTheme(colorScheme = colors, content = content)
}
