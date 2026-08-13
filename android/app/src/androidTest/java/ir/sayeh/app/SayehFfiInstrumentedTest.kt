package ir.sayeh.app

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import ir.sayeh.ffi.CarrierChoice
import ir.sayeh.ffi.hidePasswordFile
import ir.sayeh.ffi.hidePasswordText
import ir.sayeh.ffi.revealPasswordMessage
import ir.sayeh.ffi.scanMessage
import ir.sayeh.ffi.stripMessageSafe
import kotlin.random.Random
import kotlin.system.measureTimeMillis
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SayehFfiInstrumentedTest {
    @Test
    fun fiveHundredBytesRoundTripThroughRustOnDevice() {
        val cover = "سلام خوبی؟"
        val payload = Random(0x5A9E).nextBytes(500)
        val password = "device-round-trip-password"
        var elapsed = 0L

        val hidden = hidePasswordFile(
            cover = cover,
            fileName = "sample.bin",
            bytes = payload,
            password = password,
            carrier = CarrierChoice.ZERO_WIDTH,
            createdAt = 1_786_581_600UL,
        )
        lateinit var openedBytes: ByteArray
        elapsed = measureTimeMillis {
            val opened = revealPasswordMessage(hidden.text, password)
            assertFalse(opened.isText)
            assertEquals("sample.bin", opened.fileName)
            openedBytes = opened.bytes
        }

        assertArrayEquals(payload, openedBytes)
        assertEquals(cover, stripMessageSafe(hidden.text))
        assertEquals(500UL, hidden.contentBytes)
        assertTrue(hidden.carrierSymbols > 0UL)
        assertFalse(hidden.compressed)
        assertEquals(CarrierChoice.ZERO_WIDTH, scanMessage(hidden.text).carrier)
        Log.i("SayehDeviceTest", "argon_open_ms=$elapsed carrier_symbols=${hidden.carrierSymbols}")
    }

    @Test
    fun emptyPasswordIsAccepted() {
        val hidden = hidePasswordText(
            cover = "بدون رمز",
            secret = "concealment only",
            password = "",
            carrier = CarrierChoice.ZERO_WIDTH,
            createdAt = 1_786_581_600UL,
        )
        val opened = revealPasswordMessage(hidden.text, "")
        assertEquals("concealment only", opened.text)
    }

    @Test
    fun viewModelOpensItsGeneratedTextWithoutPassword() = runBlocking {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val viewModel = SayehViewModel()
        instrumentation.runOnMainSync {
            viewModel.setCover("سلام خوبی؟")
            viewModel.setSecret("synthetic UI message")
            viewModel.hide()
        }
        val hidden = withTimeout(10_000) {
            viewModel.state.first { !it.busy && it.hidden != null }.hidden
        }
        assertTrue(hidden != null)
        instrumentation.runOnMainSync {
            viewModel.selectTab(WorkspaceTab.OPEN)
            viewModel.setReceived(requireNotNull(hidden).text)
            viewModel.open()
        }
        val opened = withTimeout(10_000) {
            viewModel.state.first { !it.busy && it.opened != null }.opened
        }
        assertEquals("synthetic UI message", opened?.text)
    }
}
