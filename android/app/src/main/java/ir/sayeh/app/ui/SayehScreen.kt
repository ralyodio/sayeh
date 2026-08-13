package ir.sayeh.app.ui

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ir.sayeh.app.R
import ir.sayeh.app.SayehUiState
import ir.sayeh.app.SayehViewModel
import ir.sayeh.app.UiNotice
import ir.sayeh.app.WorkspaceTab
import ir.sayeh.ffi.CarrierChoice
import ir.sayeh.ffi.PayloadMode

@Composable
fun SayehScreen(
    viewModel: SayehViewModel,
    onShare: (String) -> Unit,
    onCopy: (String) -> Unit,
    onPaste: () -> String?,
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    Scaffold { insets ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(insets)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 20.dp, vertical = 16.dp),
        ) {
            Text(
                text = stringResource(R.string.app_name),
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.SemiBold,
            )
            Text(
                text = stringResource(R.string.app_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(20.dp))
            TabChooser(state.tab, viewModel::selectTab)
            Spacer(Modifier.height(20.dp))

            when (state.tab) {
                WorkspaceTab.HIDE -> HideWorkspace(state, viewModel, onShare, onCopy)
                WorkspaceTab.OPEN -> OpenWorkspace(state, viewModel, onShare, onCopy, onPaste)
            }

            if (state.busy) {
                Spacer(Modifier.height(18.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Spacer(Modifier.height(8.dp))
                Text(stringResource(R.string.working), style = MaterialTheme.typography.bodySmall)
            }

            state.notice?.let {
                Spacer(Modifier.height(18.dp))
                NoticeCard(it, state)
            }
            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun TabChooser(selected: WorkspaceTab, onSelect: (WorkspaceTab) -> Unit) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        TabButton(
            selected = selected == WorkspaceTab.HIDE,
            label = stringResource(R.string.hide_tab),
            onClick = { onSelect(WorkspaceTab.HIDE) },
            modifier = Modifier.weight(1f).testTag("hide_tab"),
        )
        TabButton(
            selected = selected == WorkspaceTab.OPEN,
            label = stringResource(R.string.open_tab),
            onClick = { onSelect(WorkspaceTab.OPEN) },
            modifier = Modifier.weight(1f).testTag("open_tab"),
        )
    }
}

@Composable
private fun TabButton(selected: Boolean, label: String, onClick: () -> Unit, modifier: Modifier) {
    if (selected) {
        Button(onClick = onClick, modifier = modifier) { Text(label) }
    } else {
        OutlinedButton(onClick = onClick, modifier = modifier) { Text(label) }
    }
}

@Composable
private fun HideWorkspace(
    state: SayehUiState,
    viewModel: SayehViewModel,
    onShare: (String) -> Unit,
    onCopy: (String) -> Unit,
) {
    OutlinedTextField(
        value = state.cover,
        onValueChange = viewModel::setCover,
        label = { Text(stringResource(R.string.cover_label)) },
        supportingText = { Text(stringResource(R.string.cover_hint)) },
        minLines = 2,
        maxLines = 5,
        modifier = Modifier.fillMaxWidth().testTag("cover_input"),
        enabled = !state.busy,
    )
    Spacer(Modifier.height(12.dp))
    OutlinedTextField(
        value = state.secret,
        onValueChange = viewModel::setSecret,
        label = { Text(stringResource(R.string.secret_label)) },
        minLines = 3,
        maxLines = 8,
        modifier = Modifier.fillMaxWidth().testTag("secret_input"),
        enabled = !state.busy,
    )
    Spacer(Modifier.height(12.dp))
    PasswordField(state.password, viewModel::setPassword, !state.busy, "hide_password")
    Spacer(Modifier.height(16.dp))
    CarrierChooser(state.carrier, viewModel::setCarrier, !state.busy)
    Spacer(Modifier.height(18.dp))
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Button(
            onClick = viewModel::hide,
            enabled = !state.busy,
            modifier = Modifier.weight(1f).testTag("hide_button"),
        ) {
            Text(stringResource(R.string.hide_action))
        }
        OutlinedButton(onClick = viewModel::clearCurrent, enabled = !state.busy) {
            Text(stringResource(R.string.clear_action))
        }
    }

    state.hidden?.let { hidden ->
        Spacer(Modifier.height(18.dp))
        HorizontalDivider()
        Spacer(Modifier.height(18.dp))
        OutlinedTextField(
            value = hidden.text,
            onValueChange = {},
            readOnly = true,
            minLines = 3,
            maxLines = 7,
            label = { Text(stringResource(R.string.hidden_ready)) },
            modifier = Modifier.fillMaxWidth().testTag("hidden_output"),
        )
        Spacer(Modifier.height(10.dp))
        ActionRow(hidden.text, onShare, onCopy, "hidden")
        Spacer(Modifier.height(10.dp))
        OutlinedButton(
            onClick = viewModel::openGenerated,
            modifier = Modifier.fillMaxWidth().testTag("open_generated"),
        ) {
            Text(stringResource(R.string.open_generated_action))
        }
    }
}

@Composable
private fun OpenWorkspace(
    state: SayehUiState,
    viewModel: SayehViewModel,
    onShare: (String) -> Unit,
    onCopy: (String) -> Unit,
    onPaste: () -> String?,
) {
    OutlinedTextField(
        value = state.received,
        onValueChange = viewModel::setReceived,
        label = { Text(stringResource(R.string.incoming_label)) },
        minLines = 4,
        maxLines = 9,
        modifier = Modifier.fillMaxWidth().testTag("received_input"),
        enabled = !state.busy,
    )
    Spacer(Modifier.height(10.dp))
    OutlinedButton(
        onClick = { viewModel.paste(onPaste()) },
        enabled = !state.busy,
        modifier = Modifier.fillMaxWidth().testTag("paste_button"),
    ) {
        Text(stringResource(R.string.paste_action))
    }
    Spacer(Modifier.height(12.dp))
    PasswordField(state.password, viewModel::setPassword, !state.busy, "open_password")
    Spacer(Modifier.height(18.dp))
    Button(
        onClick = viewModel::open,
        enabled = !state.busy,
        modifier = Modifier.fillMaxWidth().testTag("open_button"),
    ) {
        Text(stringResource(R.string.open_action))
    }
    Spacer(Modifier.height(10.dp))
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        OutlinedButton(
            onClick = viewModel::scan,
            enabled = !state.busy,
            modifier = Modifier.weight(1f),
        ) {
            Text(stringResource(R.string.scan_action))
        }
        OutlinedButton(
            onClick = viewModel::safeStrip,
            enabled = !state.busy,
            modifier = Modifier.weight(1f),
        ) {
            Text(stringResource(R.string.strip_action))
        }
        OutlinedButton(onClick = viewModel::clearCurrent, enabled = !state.busy) {
            Text(stringResource(R.string.clear_action))
        }
    }

    state.opened?.let { opened ->
        Spacer(Modifier.height(18.dp))
        HorizontalDivider()
        Spacer(Modifier.height(18.dp))
        if (opened.isText) {
            val text = opened.text.orEmpty()
            OutlinedTextField(
                value = text,
                onValueChange = {},
                readOnly = true,
                minLines = 3,
                maxLines = 8,
                label = { Text(stringResource(R.string.opened_ready)) },
                modifier = Modifier.fillMaxWidth().testTag("opened_output"),
            )
            Spacer(Modifier.height(10.dp))
            ActionRow(text, onShare, onCopy, "opened")
        }
    }
}

@Composable
private fun PasswordField(
    value: String,
    onChange: (String) -> Unit,
    enabled: Boolean,
    tag: String,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(stringResource(R.string.password_label)) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            imeAction = ImeAction.Done,
        ),
        singleLine = true,
        modifier = Modifier.fillMaxWidth().testTag(tag),
        enabled = enabled,
    )
}

@Composable
private fun CarrierChooser(
    selected: CarrierChoice,
    onSelect: (CarrierChoice) -> Unit,
    enabled: Boolean,
) {
    Text(stringResource(R.string.carrier_label), style = MaterialTheme.typography.labelLarge)
    Spacer(Modifier.height(8.dp))
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        CarrierChoice.entries.forEach { carrier ->
            val label = when (carrier) {
                CarrierChoice.ZERO_WIDTH -> R.string.carrier_zero_width
                CarrierChoice.ZERO_WIDTH_COMPAT -> R.string.carrier_compat
                CarrierChoice.VARIATION_SELECTORS -> R.string.carrier_variation
                CarrierChoice.UNICODE_TAGS -> R.string.carrier_tags
            }
            FilterChip(
                selected = selected == carrier,
                onClick = { onSelect(carrier) },
                label = { Text(stringResource(label)) },
                enabled = enabled,
            )
        }
    }
}

@Composable
private fun ActionRow(
    text: String,
    onShare: (String) -> Unit,
    onCopy: (String) -> Unit,
    tagPrefix: String,
) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
        Button(
            onClick = { onShare(text) },
            modifier = Modifier.weight(1f).testTag("${tagPrefix}_share"),
        ) {
            Text(stringResource(R.string.share_action))
        }
        OutlinedButton(
            onClick = { onCopy(text) },
            modifier = Modifier.weight(1f).testTag("${tagPrefix}_copy"),
        ) {
            Text(stringResource(R.string.copy_action))
        }
    }
}

@Composable
private fun NoticeCard(notice: UiNotice, state: SayehUiState) {
    val isError = notice in setOf(
        UiNotice.MISSING_HIDE_INPUT,
        UiNotice.MISSING_OPEN_INPUT,
        UiNotice.CLIPBOARD_EMPTY,
        UiNotice.HIDE_FAILED,
        UiNotice.OPEN_FAILED,
        UiNotice.SCAN_FAILED,
    )
    val text = when (notice) {
        UiNotice.MISSING_HIDE_INPUT -> stringResource(R.string.missing_hide_input)
        UiNotice.MISSING_OPEN_INPUT -> stringResource(R.string.missing_open_input)
        UiNotice.CLIPBOARD_EMPTY -> stringResource(R.string.clipboard_empty)
        UiNotice.HIDDEN -> state.hidden?.let {
            stringResource(
                R.string.hidden_details,
                it.contentBytes.toLong(),
                it.containerBytes.toLong(),
                it.carrierSymbols.toLong(),
            )
        }.orEmpty()
        UiNotice.OPENED -> state.opened?.let {
            if (it.isText) {
                stringResource(R.string.opened_ready)
            } else {
                stringResource(
                    R.string.file_opened,
                    it.fileName.orEmpty(),
                    it.bytes.size.toLong(),
                )
            }
        }.orEmpty()
        UiNotice.SCANNED -> state.scan?.let {
            val mode = if (it.mode == PayloadMode.PASSWORD) {
                stringResource(R.string.scan_password)
            } else {
                stringResource(R.string.scan_contact)
            }
            stringResource(
                R.string.scan_ready,
                it.wireVersion.toInt(),
                mode,
                it.containerBytes.toLong(),
                it.carrierSymbols.toLong(),
            )
        }.orEmpty()
        UiNotice.STRIPPED -> stringResource(R.string.stripped_ready)
        UiNotice.HIDE_FAILED -> stringResource(R.string.hide_failed)
        UiNotice.OPEN_FAILED -> stringResource(R.string.open_failed)
        UiNotice.SCAN_FAILED -> stringResource(R.string.scan_failed)
    }
    val colors = if (isError) {
        CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.errorContainer,
            contentColor = MaterialTheme.colorScheme.onErrorContainer,
        )
    } else {
        CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
        )
    }
    Card(colors = colors, modifier = Modifier.fillMaxWidth()) {
        Text(text, modifier = Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium)
    }
}
