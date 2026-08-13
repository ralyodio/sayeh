package ir.sayeh.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ir.sayeh.ffi.CarrierChoice
import ir.sayeh.ffi.HiddenMessage
import ir.sayeh.ffi.OpenedMessage
import ir.sayeh.ffi.ScanReport
import ir.sayeh.ffi.hidePasswordText
import ir.sayeh.ffi.revealPasswordMessage
import ir.sayeh.ffi.scanMessage
import ir.sayeh.ffi.stripMessageSafe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

enum class WorkspaceTab {
    HIDE,
    OPEN,
}

enum class UiNotice {
    MISSING_HIDE_INPUT,
    MISSING_OPEN_INPUT,
    CLIPBOARD_EMPTY,
    HIDDEN,
    OPENED,
    SCANNED,
    STRIPPED,
    HIDE_FAILED,
    OPEN_FAILED,
    SCAN_FAILED,
}

data class SayehUiState(
    val tab: WorkspaceTab = WorkspaceTab.HIDE,
    val cover: String = "",
    val secret: String = "",
    val received: String = "",
    val password: String = "",
    val carrier: CarrierChoice = CarrierChoice.ZERO_WIDTH,
    val busy: Boolean = false,
    val hidden: HiddenMessage? = null,
    val opened: OpenedMessage? = null,
    val scan: ScanReport? = null,
    val notice: UiNotice? = null,
)

class SayehViewModel : ViewModel() {
    private val mutableState = MutableStateFlow(SayehUiState())
    val state = mutableState.asStateFlow()

    fun selectTab(tab: WorkspaceTab) = mutate { copy(tab = tab, notice = null) }

    fun setCover(value: String) = mutate { copy(cover = value, hidden = null, notice = null) }

    fun setSecret(value: String) = mutate { copy(secret = value, hidden = null, notice = null) }

    fun setReceived(value: String) = mutate {
        copy(received = value, opened = null, scan = null, notice = null)
    }

    fun setPassword(value: String) = mutate {
        copy(password = value, hidden = null, opened = null, notice = null)
    }

    fun setCarrier(value: CarrierChoice) = mutate {
        copy(carrier = value, hidden = null, notice = null)
    }

    fun receive(value: String) = mutate {
        copy(
            tab = WorkspaceTab.OPEN,
            received = value,
            opened = null,
            scan = null,
            notice = null,
        )
    }

    fun paste(value: String?) {
        if (value.isNullOrEmpty()) {
            mutate { copy(notice = UiNotice.CLIPBOARD_EMPTY) }
        } else {
            receive(value)
        }
    }

    fun openGenerated() {
        val text = mutableState.value.hidden?.text ?: return
        receive(text)
    }

    fun clearCurrent() = mutate {
        when (tab) {
            WorkspaceTab.HIDE -> copy(cover = "", secret = "", password = "", hidden = null, notice = null)
            WorkspaceTab.OPEN -> copy(received = "", password = "", opened = null, scan = null, notice = null)
        }
    }

    fun hide() {
        val snapshot = mutableState.value
        if (snapshot.secret.isEmpty()) {
            mutate { copy(notice = UiNotice.MISSING_HIDE_INPUT) }
            return
        }
        mutate { copy(busy = true, hidden = null, notice = null) }
        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.Default) {
                    hidePasswordText(
                        cover = snapshot.cover,
                        secret = snapshot.secret,
                        password = snapshot.password,
                        carrier = snapshot.carrier,
                        createdAt = (System.currentTimeMillis() / 1_000L).toULong(),
                    )
                }
            }
            mutate {
                result.fold(
                    onSuccess = { copy(busy = false, hidden = it, notice = UiNotice.HIDDEN) },
                    onFailure = { copy(busy = false, hidden = null, notice = UiNotice.HIDE_FAILED) },
                )
            }
        }
    }

    fun open() {
        val snapshot = mutableState.value
        if (snapshot.received.isEmpty()) {
            mutate { copy(notice = UiNotice.MISSING_OPEN_INPUT) }
            return
        }
        mutate { copy(busy = true, opened = null, notice = null) }
        viewModelScope.launch {
            val result = runCatching {
                withContext(Dispatchers.Default) {
                    revealPasswordMessage(snapshot.received, snapshot.password)
                }
            }
            mutate {
                result.fold(
                    onSuccess = { copy(busy = false, opened = it, notice = UiNotice.OPENED) },
                    onFailure = { copy(busy = false, opened = null, notice = UiNotice.OPEN_FAILED) },
                )
            }
        }
    }

    fun scan() {
        val text = mutableState.value.received
        if (text.isEmpty()) {
            mutate { copy(notice = UiNotice.MISSING_OPEN_INPUT) }
            return
        }
        mutate { copy(busy = true, scan = null, notice = null) }
        viewModelScope.launch {
            val result = runCatching { withContext(Dispatchers.Default) { scanMessage(text) } }
            mutate {
                result.fold(
                    onSuccess = { copy(busy = false, scan = it, notice = UiNotice.SCANNED) },
                    onFailure = { copy(busy = false, scan = null, notice = UiNotice.SCAN_FAILED) },
                )
            }
        }
    }

    fun safeStrip() {
        mutate {
            copy(
                received = stripMessageSafe(received),
                opened = null,
                scan = null,
                notice = UiNotice.STRIPPED,
            )
        }
    }

    private fun mutate(block: SayehUiState.() -> SayehUiState) {
        mutableState.update(block)
    }
}
